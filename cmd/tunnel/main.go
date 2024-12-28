package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"cdr.dev/slog"
	"cdr.dev/slog/sloggers/sloghuman"
	"github.com/coder/wgtunnel/buildinfo"
	"github.com/coder/wgtunnel/tunnelsdk"
)

func main() {
	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"V"},
		Usage:   "Print the version.",
	}

	app := &cli.App{
		Name:      "tunnel",
		Usage:     "run a wgtunnel client",
		ArgsUsage: "<target-address (e.g. 127.0.0.1:8080)>",
		Version:   buildinfo.Version(),
		Commands: []*cli.Command{
			{
				Name:  "version",
				Usage: "Print the version.",
				Action: func(ctx *cli.Context) error {
					fmt.Println(buildinfo.Version())
					return nil
				},
			},
			{
				Name:  "genkey",
				Usage: "Generate a new wireguard key.",
				Action: func(ctx *cli.Context) error {
					key, err := tunnelsdk.GeneratePrivateKey()
					if err != nil {
						return xerrors.Errorf("generate key: %w", err)
					}
					fmt.Println(key.String())
					return nil
				},
			},
			{
				Name:  "run",
				Usage: "Run the tunnel client.",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "Enable verbose logging.",
						EnvVars: []string{"TUNNEL_VERBOSE"},
					},
					&cli.StringFlag{
						Name:    "api-url",
						Usage:   "The base URL of the tunnel API.",
						EnvVars: []string{"TUNNEL_API_URL"},
					},
					&cli.StringFlag{
						Name:    "wireguard-key",
						Aliases: []string{"wg-key"},
						Usage:   "The private key for the wireguard client. It should be base64 encoded. You must specify this or wireguard-key-file.",
						EnvVars: []string{"TUNNEL_WIREGUARD_KEY"},
					},
					&cli.StringFlag{
						Name:    "wireguard-key-file",
						Aliases: []string{"wg-key-file"},
						Usage:   "The file containing the private key for the wireguard client. It should contain a base64 encoded key. The file will be created and populated with a fresh key if it does not exist. You must specify this or wireguard-key.",
						EnvVars: []string{"TUNNEL_WIREGUARD_KEY_FILE"},
					},
					&cli.StringFlag{
						Name:    "basic-auth-user",
						Usage:   "The username for basic auth.",
						EnvVars: []string{"TUNNEL_BASIC_AUTH_USER"},
					},
					&cli.StringFlag{
						Name:    "basic-auth-pass",
						Usage:   "The password for basic auth.",
						EnvVars: []string{"TUNNEL_BASIC_AUTH_PASS"},
					},
					&cli.StringFlag{
						Name:    "basic-auth-pass-file",
						Usage:   "The file containing the password for basic auth. The file will be created and populated with a fresh password if it does not exist. You must specify this or basic-auth-pass.",
						EnvVars: []string{"TUNNEL_BASIC_AUTH_PASS_FILE"},
					},
				},
				Action: runApp,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func runApp(ctx *cli.Context) error {
	var (
		verbose           = ctx.Bool("verbose")
		apiURL            = ctx.String("api-url")
		wireguardKey      = ctx.String("wireguard-key")
		wireguardKeyFile  = ctx.String("wireguard-key-file")
		basicAuthUser     = ctx.String("basic-auth-user")
		basicAuthPass     = ctx.String("basic-auth-pass")
		basicAuthPassFile = ctx.String("basic-auth-pass-file")
	)
	if apiURL == "" {
		return xerrors.New("api-url is required. See --help for more information.")
	}
	if wireguardKey == "" && wireguardKeyFile == "" {
		return xerrors.New("wireguard-key or wireguard-key-file is required. See --help for more information.")
	}
	if wireguardKey != "" && wireguardKeyFile != "" {
		return xerrors.New("Only one of wireguard-key or wireguard-key-file can be specified. See --help for more information.")
	}

	if ctx.Args().Len() != 1 {
		return xerrors.New("exactly one argument (target-address) is required. See --help for more information.")
	}
	targetAddress := ctx.Args().Get(0)
	if targetAddress == "" {
		return xerrors.New("target-address is empty")
	}
	_, _, err := net.SplitHostPort(targetAddress)
	if err != nil {
		return xerrors.Errorf("target-address %q is not a valid host:port: %w", targetAddress, err)
	}

	logger := slog.Make(sloghuman.Sink(os.Stderr)).Leveled(slog.LevelInfo)
	if verbose {
		logger = logger.Leveled(slog.LevelDebug)
	}

	apiURLParsed, err := url.Parse(apiURL)
	if err != nil {
		return xerrors.Errorf("failed to parse api-url %q: %w", apiURL, err)
	}

	if wireguardKeyFile != "" {
		fileBytes, err := os.ReadFile(wireguardKeyFile)
		if errors.Is(err, os.ErrNotExist) {
			key, err := tunnelsdk.GeneratePrivateKey()
			if err != nil {
				return xerrors.Errorf("failed to generate wireguard key: %w", err)
			}

			fileBytes = []byte(key.String())
			err = os.WriteFile(wireguardKeyFile, fileBytes, 0600)
			if err != nil {
				return xerrors.Errorf("failed to write wireguard key to file %q: %w", wireguardKeyFile, err)
			}
		} else if err != nil {
			return xerrors.Errorf("failed to read wireguard-key-file %q: %w", wireguardKeyFile, err)
		}
		wireguardKey = string(fileBytes)
	}

	wireguardKeyParsed, err := tunnelsdk.ParsePrivateKey(wireguardKey)
	if err != nil {
		return xerrors.Errorf("could not parse wireguard-key or wireguard-key-file: %w", err)
	}

	if basicAuthPassFile != "" {
		fileBytes, err := os.ReadFile(basicAuthPassFile)
		if errors.Is(err, os.ErrNotExist) {
			return xerrors.Errorf("basic-auth-pass-file %q does not exist", basicAuthPassFile)
		} else if err != nil {
			return xerrors.Errorf("failed to read basic-auth-pass-file %q: %w", basicAuthPassFile, err)
		}
		basicAuthPass = string(fileBytes)
	}

	client := tunnelsdk.New(apiURLParsed, basicAuthUser, basicAuthPass)
	tunnel, err := client.LaunchTunnel(ctx.Context, tunnelsdk.TunnelConfig{
		Log:        logger,
		PrivateKey: wireguardKeyParsed,
	})
	if err != nil {
		return xerrors.Errorf("launch tunnel: %w", err)
	}
	defer func() {
		err := tunnel.Close()
		if err != nil {
			logger.Error(ctx.Context, "close tunnel", slog.Error(err))
		}
	}()

	_, _ = fmt.Fprintln(os.Stderr, "Tunnel is ready. You can now connect to one of the following URLs:")
	_, _ = fmt.Fprintln(os.Stderr, "  -", tunnel.URL.String())
	for _, u := range tunnel.OtherURLs {
		_, _ = fmt.Fprintln(os.Stderr, "  -", u.String())
	}

	// Start forwarding traffic to/from the tunnel.
	go func() {
		for {
			conn, err := tunnel.Listener.Accept()
			if err != nil {
				logger.Error(ctx.Context, "close tunnel", slog.Error(err))
				tunnel.Close()
				return
			}

			go func() {
				defer conn.Close()

				dialCtx, dialCancel := context.WithTimeout(ctx.Context, 10*time.Second)
				defer dialCancel()

				targetConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", targetAddress)
				if err != nil {
					logger.Warn(ctx.Context, "could not dial target", slog.F("target_address", targetAddress), slog.Error(err))
					return
				}
				defer targetConn.Close()

				go func() {
					_, err := io.Copy(targetConn, conn)
					if err != nil && !xerrors.Is(err, io.EOF) {
						logger.Warn(ctx.Context, "could not copy from tunnel to target", slog.Error(err))
					}
				}()

				_, err = io.Copy(conn, targetConn)
				if err != nil && !xerrors.Is(err, io.EOF) {
					logger.Warn(ctx.Context, "could not copy from target to tunnel", slog.Error(err))
				}
			}()
		}
	}()

	_, _ = fmt.Printf("\nTunnel is ready! You can now connect to %s\n", tunnel.URL.String())

	notifyCtx, notifyStop := signal.NotifyContext(ctx.Context, InterruptSignals...)
	defer notifyStop()

	select {
	case <-notifyCtx.Done():
		_, _ = fmt.Printf("\nClosing tunnel due to signal...\n")
		return tunnel.Close()
	case <-tunnel.Wait():
	}

	return nil
}
