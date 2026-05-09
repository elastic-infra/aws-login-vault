package cli

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func newListCmd(sf *storeFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List cached profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(sf)
		},
	}
}

func runList(sf *storeFlags) error {
	store, err := openStore(sf)
	if err != nil {
		return err
	}
	profiles, err := store.List()
	if err != nil {
		return err
	}
	if len(profiles) == 0 {
		fmt.Fprintln(os.Stderr, "No cached profiles. Run `aws-login-vault login --profile NAME`.")
		return nil
	}
	sort.Strings(profiles)

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PROFILE\tREGION\tSESSION ARN\tREMAINING")
	for _, p := range profiles {
		sess, err := store.Load(p)
		if err != nil {
			fmt.Fprintf(tw, "%s\t(error: %v)\t\t\n", p, err)
			continue
		}
		remaining := time.Until(sess.Expiration).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			p, sess.Region, sess.SessionARN, remaining)
	}
	return tw.Flush()
}
