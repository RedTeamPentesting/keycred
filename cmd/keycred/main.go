package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RedTeamPentesting/keycred"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/ldapauth"
)

var version string

//nolint:maintidx
func run() error {
	var (
		debug    bool
		authOpts = &adauth.Options{
			Debug: adauth.NewDebugFunc(&debug, os.Stderr, true),
		}
		ldapOpts = &ldapauth.Options{
			Debug: adauth.NewDebugFunc(&debug, os.Stderr, true),
		}
		targetUser  string
		socksServer = os.Getenv("SOCKS5_SERVER")
	)

	cobra.EnableCommandSorting = false
	rootCmd := &cobra.Command{
		Use:           binaryName(),
		Short:         "Create and manage KeyCredentialLinks",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) (err error) {
			ldapOpts.SetDialer(adauth.DialerWithSOCKS5ProxyIfSet(socksServer, nil))

			return nil
		},
	}

	flags := rootCmd.PersistentFlags()
	authOpts.RegisterFlags(flags)
	ldapOpts.RegisterFlags(flags)
	flags.BoolVar(&debug, "debug", false, "Enable debug output")
	flags.StringVarP(&targetUser, "target", "t", "", "Target `user` (default is the authenticating user)")
	flags.StringVar(&socksServer, "socks", socksServer, "SOCKS5 server `address`")

	var (
		deviceID                 string
		save                     string
		validatedWriteCompatible bool
		derFormatted             bool
		keySize                  int
		noDeviceID               bool
		stdout                   bool
		pfxPassword              string
	)

	addCmd := cobra.Command{
		Use:           "add",
		Short:         "Create certificate/key and register it in LDAP",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !noDeviceID && deviceID == "" {
				deviceID = uuid.New().String()
			}

			conn, err := ldapauth.Connect(cmd.Context(), authOpts, ldapOpts)
			if err != nil {
				return fmt.Errorf("LDAP connect: %w", err)
			}

			defer conn.Close() //nolint:errcheck

			if targetUser == "" {
				targetUser = authOpts.UPN()
			}

			return addKeyCredential(conn, targetUser, keySize, deviceID,
				derFormatted, validatedWriteCompatible, stdout, save, pfxPassword)
		},
	}

	addFlags := addCmd.PersistentFlags()
	addFlags.StringVar(&deviceID, "device-id", "", "Device ID")
	addFlags.BoolVar(&validatedWriteCompatible, "validated-write-compatible", false,
		"Generate KeyCredentialLink that is strictly compatible with WriteValidate rules")
	addFlags.BoolVar(&derFormatted, "der-formatted", false,
		"Generate KeyCredentialLink with DER-formatted public key")
	addFlags.BoolVar(&stdout, "stdout", false, "Print PFX to stdout instead of writing it to file")
	addFlags.StringVar(&save, "save", "", "Save PFX to this `directory/file`")
	addFlags.IntVar(&keySize, "key-size", 2048, "Key size")
	addFlags.BoolVar(&noDeviceID, "no-device-id", noDeviceID, "Omit device ID")
	addFlags.StringVar(&pfxPassword, "pfx-password", pfxPassword, "PFX password")

	rootCmd.AddCommand(&addCmd)

	var unsafe bool

	addRawCmd := cobra.Command{
		Use:           "add-raw <B:123:00020[...]>",
		Short:         "Register a raw DN-Binary string in LDAP",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := ldapauth.Connect(cmd.Context(), authOpts, ldapOpts)
			if err != nil {
				return fmt.Errorf("LDAP connect: %w", err)
			}

			defer conn.Close() //nolint:errcheck

			if targetUser == "" {
				targetUser = authOpts.UPN()
			}

			return addRawKeyCredential(conn, targetUser, args[0], unsafe)
		},
	}

	addRawFlags := addRawCmd.PersistentFlags()
	addRawFlags.BoolVar(&unsafe, "unsafe", false, "Do not try to parse KeyCredentialLink before adding")

	rootCmd.AddCommand(&addRawCmd)

	var (
		raw bool
		all bool
	)

	listCmd := cobra.Command{
		Use:           "list",
		Short:         "List KeyCredentialLinks of a single user or all users",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := ldapauth.Connect(cmd.Context(), authOpts, ldapOpts)
			if err != nil {
				return fmt.Errorf("LDAP connect: %w", err)
			}

			defer conn.Close() //nolint:errcheck

			if all {
				return listAllKeyCredentials(conn, raw)
			}

			if targetUser == "" {
				targetUser = authOpts.UPN()
			}

			return listKeyCredentialsOfUser(conn, targetUser, raw)
		},
	}

	listFlags := listCmd.PersistentFlags()
	listFlags.BoolVar(&raw, "raw", false, "Include raw DNWithBinary value")
	listFlags.BoolVar(&all, "all", false, "List KeyCredentials of all users")

	rootCmd.AddCommand(&listCmd)

	var keyID string

	removeCmd := cobra.Command{
		Use:           "remove",
		Short:         "Remove a single KeyCredentialLink of a user",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := ldapauth.Connect(cmd.Context(), authOpts, ldapOpts)
			if err != nil {
				return fmt.Errorf("LDAP connect: %w", err)
			}

			defer conn.Close() //nolint:errcheck

			if targetUser == "" {
				targetUser = authOpts.UPN()
			}

			return removeKeyCredential(conn, targetUser, deviceID, keyID, nil)
		},
	}

	removeFlags := removeCmd.PersistentFlags()
	removeFlags.StringVar(&deviceID, "device-id", "", "Device ID")
	removeFlags.StringVar(&keyID, "key-id", "", "Key ID")

	rootCmd.AddCommand(&removeCmd)

	clearCmd := cobra.Command{
		Use:           "clear",
		Short:         "Remove all KeyCredentialLinks of a user",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := ldapauth.Connect(cmd.Context(), authOpts, ldapOpts)
			if err != nil {
				return fmt.Errorf("LDAP connect: %w", err)
			}
			defer conn.Close() //nolint:errcheck

			if targetUser == "" {
				targetUser = authOpts.UPN()
			}

			return clearKeyCredential(conn, targetUser)
		},
	}

	rootCmd.AddCommand(&clearCmd)

	authCmd := &cobra.Command{
		Use:           "auth --pfx cert.pfx",
		Short:         "Authenticate and retrieve the NT hash using PKINIT (requires --pfx)",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			creds, err := authOpts.NoTarget()
			if err != nil {
				return err
			}

			return authenticate(cmd.Context(), creds)
		},
	}

	rootCmd.AddCommand(authCmd)

	burnCmd := &cobra.Command{
		Use:           "burn --pfx <keycredentiallinkcert.pfx>",
		Short:         "Authenticate to obtain hash/ticket and clear KeyCredentialLink (requires --pfx)",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			creds, err := authOpts.NoTarget()
			if err != nil {
				return err
			}

			dc, err := creds.DC(cmd.Context(), "ldap")
			if err != nil {
				return fmt.Errorf("find DC: %w", err)
			}

			rsaKey, ok := creds.ClientCertKey.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("cannot use %T because PKINIT requires an RSA key", creds.ClientCertKey)
			}

			err = authenticate(cmd.Context(), creds)
			if err != nil {
				return err
			}

			dc.UseKerberos = true

			conn, err := ldapauth.ConnectTo(cmd.Context(), creds, dc, ldapOpts)
			if err != nil {
				return fmt.Errorf("LDAP connect: %w", err)
			}

			defer conn.Close() //nolint:errcheck

			err = removeKeyCredential(conn, creds.UPN(), "", "", &rsaKey.PublicKey)
			if err != nil {
				return fmt.Errorf("remove KeyCredentialLink: %w", err)
			}

			return nil
		},
	}

	rootCmd.AddCommand(burnCmd)

	var backupFile string

	backupCmd := cobra.Command{
		Use:           "backup",
		Short:         "Backup all KeyCredentialLinks of a user",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := ldapauth.Connect(cmd.Context(), authOpts, ldapOpts)
			if err != nil {
				return fmt.Errorf("LDAP connect: %w", err)
			}

			defer conn.Close() //nolint:errcheck

			if targetUser == "" {
				targetUser = authOpts.UPN()
			}

			return backupKeyCredentialsOfUser(conn, targetUser, backupFile, targetUser == authOpts.UPN())
		},
	}

	backupFlags := backupCmd.PersistentFlags()
	backupFlags.StringVarP(&backupFile, "file", "f", "", "Backup file name")

	rootCmd.AddCommand(&backupCmd)

	var force bool

	restoreCmd := cobra.Command{
		Use:           "restore <backup file>",
		Short:         "Restore the KeyCredentialLinks from a backup file",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := ldapauth.Connect(cmd.Context(), authOpts, ldapOpts)
			if err != nil {
				return fmt.Errorf("LDAP connect: %w", err)
			}

			defer conn.Close() //nolint:errcheck

			if targetUser == "" {
				targetUser = authOpts.UPN()
			}

			return restoreBackup(conn, args[0], force)
		},
	}

	restoreFlags := restoreCmd.PersistentFlags()
	restoreFlags.BoolVar(&force, "force", false, "Skip backup sanity checks")

	rootCmd.AddCommand(&restoreCmd)

	registerCmd := &cobra.Command{
		Use:           "register <cert.pfx>",
		Short:         "Register the key from an existing PFX file",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := ldapauth.Connect(cmd.Context(), authOpts, ldapOpts)
			if err != nil {
				return fmt.Errorf("LDAP connect: %w", err)
			}

			defer conn.Close() //nolint:errcheck

			if targetUser == "" {
				targetUser = authOpts.UPN()
			}

			return registerKeyCredential(conn, targetUser, deviceID,
				derFormatted, validatedWriteCompatible, args[0], pfxPassword)
		},
	}

	registerFlags := registerCmd.PersistentFlags()
	registerFlags.StringVar(&deviceID, "device-id", "", "Device ID")
	registerFlags.BoolVar(&validatedWriteCompatible, "validated-write-compatible", false,
		"Generate KeyCredentialLink that is strictly compatible with WriteValidate rules")
	registerFlags.BoolVar(&derFormatted, "der-formatted", false,
		"Generate KeyCredentialLink with DER-formatted public key")
	registerFlags.BoolVar(&noDeviceID, "no-device-id", noDeviceID, "Omit device ID")
	registerFlags.StringVar(&pfxPassword, "pfx-password", "", "PFX password")

	rootCmd.AddCommand(registerCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:           "parse <B:123:00020[...]DC=domain>",
		Short:         "Parse a KeyCredentialLink in DN-Binary form",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kcl, err := keycred.ParseDNWithBinary(args[0])
			if err != nil {
				return fmt.Errorf("parse KeyCredentialLink: %w", err)
			}

			fmt.Println(kcl.ColoredString())

			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:           "version",
		Short:         "Print the version",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if version != "" {
				fmt.Println(version)
			} else {
				fmt.Println("unknown")
			}
		},
	})

	return rootCmd.ExecuteContext(context.Background())
}

func binaryName() string {
	executable, err := os.Executable()
	if err == nil {
		return filepath.Base(executable)
	}

	if len(os.Args) > 0 {
		return filepath.Base(os.Args[0])
	}

	return "keycred"
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(1)
	}
}
