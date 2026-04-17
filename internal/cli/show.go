package cli

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/hkobayash/aws-login-vault/internal/keychain"
)

func newShowCmd() *cobra.Command {
	var reveal bool
	cmd := &cobra.Command{
		Use:   "show PROFILE",
		Short: "Show details of a cached profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShow(args[0], reveal)
		},
	}
	cmd.Flags().BoolVar(&reveal, "reveal", false, "print secret values in the clear")
	return cmd
}

func runShow(profile string, reveal bool) error {
	store, err := keychain.Open()
	if err != nil {
		return err
	}
	sess, err := store.Load(profile)
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "No session for profile %q\n", profile)
			return errors.New("not found")
		}
		return err
	}

	remaining := time.Until(sess.Expiration).Round(time.Second)
	fmt.Printf("profile:         %s\n", profile)
	fmt.Printf("region:          %s\n", sess.Region)
	fmt.Printf("sessionArn:      %s\n", sess.SessionARN)
	fmt.Printf("clientId:        %s\n", sess.ClientID)
	fmt.Printf("expiration:      %s (remaining: %s)\n",
		sess.Expiration.UTC().Format(time.RFC3339), remaining)

	if reveal {
		fmt.Printf("accessKeyId:     %s\n", sess.AccessKeyID)
		fmt.Printf("secretAccessKey: %s\n", sess.SecretAccessKey)
		fmt.Printf("sessionToken:    %s\n", sess.SessionToken)
		fmt.Printf("refreshToken:    %s\n", sess.RefreshToken)
		fmt.Printf("dpopKeyPem:      (%d bytes)\n%s", len(sess.DPoPKeyPEM), sess.DPoPKeyPEM)
	} else {
		fmt.Printf("accessKeyId:     %s\n", maskPrefix(sess.AccessKeyID, 4))
		fmt.Printf("secretAccessKey: %s\n", maskPresence(sess.SecretAccessKey))
		fmt.Printf("sessionToken:    %s\n", maskPresence(sess.SessionToken))
		fmt.Printf("refreshToken:    %s\n", maskPresence(sess.RefreshToken))
		fmt.Printf("dpopKeyPem:      %s (%d bytes, ES256)\n",
			maskPresence(sess.DPoPKeyPEM), len(sess.DPoPKeyPEM))
	}
	return nil
}

func maskPrefix(s string, visible int) string {
	if s == "" {
		return "(absent)"
	}
	if len(s) <= visible {
		return s + "****"
	}
	return s[:visible] + "****"
}

func maskPresence(s string) string {
	if s == "" {
		return "(absent)"
	}
	return "(present)"
}
