package cli

import (
	"fmt"
	"time"

	"github.com/coder/coder/v2/cli/cliui"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/pretty"
	"github.com/coder/serpent"
)

func (r *RootCmd) snapshot() *serpent.Command {
	var parameterFlags workspaceParameterFlags

	client := new(codersdk.Client)
	cmd := &serpent.Command{
		Annotations: workspaceCommand,
		Use:         "snapshot <workspace>",
		Short:       "Capture a point-in-time snapshot of a workspace",
		Middleware: serpent.Chain(
			serpent.RequireNArgs(1),
			r.InitClient(client),
		),
		Options: serpent.OptionSet{cliui.SkipPromptOption()},
		Handler: func(inv *serpent.Invocation) error {
			ctx := inv.Context()
			out := inv.Stdout

			workspace, err := namedWorkspace(inv.Context(), client, inv.Args[0])
			if err != nil {
				return err
			}

			//_, err = cliui.Prompt(inv, cliui.PromptOptions{
			//	Text:      "Snapshot workspace?",
			//	IsConfirm: true,
			//})
			//if err != nil {
			//	return err
			//}

			build, err := client.CreateWorkspaceBuild(ctx, workspace.ID, codersdk.CreateWorkspaceBuildRequest{
				Transition: codersdk.WorkspaceTransitionSnapshot,
			})
			if err != nil {
				return err
			}

			err = cliui.WorkspaceBuild(ctx, out, client, build.ID)
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(out,
				"\nThe %s workspace has been snapshotted at %s!\n",
				pretty.Sprint(cliui.DefaultStyles.Keyword, workspace.Name), cliui.Timestamp(time.Now()),
			)
			return nil
		},
	}

	cmd.Options = append(cmd.Options, parameterFlags.allOptions()...)

	return cmd
}
