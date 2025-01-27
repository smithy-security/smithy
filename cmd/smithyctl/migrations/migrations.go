package migrations

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/go-errors/errors"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/smithy-security/smithy/pkg/k8s"
	"github.com/smithy-security/smithy/pkg/manifests"
)

var migrationsCmdConfig = struct {
	connStr         string
	migrationsTable string
	runAsK8sJob     bool
	timeout         int
	migratiosnPath  string
}{}

var migrationsAsK8sJobConfig = struct {
	image         string
	kubeContext   string
	kubeConfig    string
	namespace     string
	leaseLockName string
	ssa           string
	dryRun        bool
	inCluster     bool
}{}

var migrationsCmd = &cobra.Command{
	Use:     "migrations",
	Short:   "A set of subcommands for managing database migrations",
	GroupID: "top-level",
}

type cmdEntrypoint func(*cobra.Command, []string) error

func init() {
	migrationsCmd.AddGroup(&cobra.Group{
		ID:    "Migrations",
		Title: "Migration Management:",
	})
	migrationsCmd.PersistentFlags().StringVar(&migrationsCmdConfig.connStr, "url", "postgres://postgres:postgres@localhost:5432", "Connection URL for the database.")
	migrationsCmd.PersistentFlags().StringVar(&migrationsCmdConfig.migrationsTable, "migrations-table", "oss-migrations", "Migrations table to inspect.")
	migrationsCmd.PersistentFlags().BoolVar(&migrationsCmdConfig.runAsK8sJob, "as-k8s-job", false, "Run command as a job in K8s")
	migrationsCmd.PersistentFlags().IntVarP(&migrationsCmdConfig.timeout, "timeout", "t", 30, "Timeout for command")
	migrationsCmd.PersistentFlags().BoolVar(&migrationsAsK8sJobConfig.dryRun, "dry-run", false, "Print the Job manifest to stdout instead of deploying it")
	migrationsCmd.PersistentFlags().BoolVar(&migrationsAsK8sJobConfig.inCluster, "in-cluster", false, "Binary is running inside a pod")
	migrationsCmd.PersistentFlags().StringVar(&migrationsAsK8sJobConfig.kubeContext, "kubecontext", "", "Use a specific kube context to execute opeations")
	migrationsCmd.PersistentFlags().StringVar(&migrationsAsK8sJobConfig.kubeConfig, "kubeconfig", "", "Path to kube config file")
	migrationsCmd.PersistentFlags().StringVar(&migrationsAsK8sJobConfig.leaseLockName, "lease-lock", "migration-job-lock", "Name for the lease lock configmap to use")
	migrationsCmd.PersistentFlags().StringVarP(&migrationsAsK8sJobConfig.namespace, "namespace", "n", "default", "Namespace where the migration job will be deployed")
	migrationsCmd.PersistentFlags().StringVarP(&migrationsAsK8sJobConfig.image, "image", "i", "", "Image to use containing smithyctl binary to run command")
	migrationsCmd.PersistentFlags().StringVar(&migrationsAsK8sJobConfig.ssa, "ssa-name", "smithyctl", "Name to use for server-side apply")
	// migrationsCmd.Flags().Bool("provide-password", false, "Provide the password via a console")
	migrationsCmd.PersistentFlags().StringVar(&migrationsCmdConfig.migratiosnPath, "migrations-path", "", "path of where to find the migrations")

}

func RegisterMigrationsSubcommands(rootCmd *cobra.Command) {
	migrationsCmd.AddCommand(inspectSubCmd)
	migrationsCmd.AddCommand(applySubCmd)
	migrationsCmd.AddCommand(revertSubCmd)

	rootCmd.AddCommand(migrationsCmd)
}

// entrypointWrapper wraps the migration commands and checks the state of the flags and the
// environment and will make sure to run the command either locally, or as a Job in the K8s cluster
// If the binary is invoked inside a pod,
func entrypointWrapper(f cmdEntrypoint) cmdEntrypoint {
	return func(cmd *cobra.Command, args []string) error {
		// set timeout on the command
		ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(migrationsCmdConfig.timeout)*time.Second)
		cmd.SetContext(ctx)
		defer cancel()

		if migrationsCmdConfig.runAsK8sJob {
			return deployMigrationJob(cmd, migrationsAsK8sJobConfig.ssa)
		}

		if migrationsAsK8sJobConfig.dryRun {
			return errors.Errorf("you can't use the `--%s` flag without the `%s` flag", cmd.Flag("dry-run").Name, cmd.Flag("as-k8s-job").Name)
		} else if migrationsAsK8sJobConfig.kubeContext != "" {
			return errors.Errorf("you can't use the `--%s` flag without the `%s` flag", cmd.Flag("kube-context").Name, cmd.Flag("as-k8s-job").Name)
		} else if migrationsAsK8sJobConfig.kubeConfig != "" {
			return errors.Errorf("you can't use the `--%s` flag without the `%s` flag", cmd.Flag("kube-config").Name, cmd.Flag("as-k8s-job").Name)
		} else if migrationsAsK8sJobConfig.image != "" {
			return errors.Errorf("you can't use the `--%s` flag without the `%s` flag", cmd.Flag("image").Name, cmd.Flag("as-k8s-job").Name)
		}

		if migrationsAsK8sJobConfig.inCluster {
			// binary has been invoked inside a pod, we need to setup the client accordingly
			restCfg, err := rest.InClusterConfig()
			if err != nil {
				return errors.Errorf("could not initialise in-cluster K8s client config: %w", err)
			}
			return grabLeaderLock(f, cmd, args, restCfg)
		}
		return f(cmd, args)
	}
}

// grabLeaderLock will grab the leader lease and then execute the actual command
func grabLeaderLock(f cmdEntrypoint, cmd *cobra.Command, args []string, restCfg *rest.Config) (err error) {
	var client *clientset.Clientset
	client, err = clientset.NewForConfig(restCfg)
	if err != nil {
		return err
	}

	leaderElectionCtx, leaderElectionCancel := context.WithCancel(cmd.Context())

	// listen for interrupts or the Linux SIGTERM signal and cancel
	// our context, which the leader election code will observe and
	// step down. channel will be closed
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		leaderElectionCancel()
	}()

	leaseID := uuid.NewString()

	// start the leader election code loop
	leaderelection.RunOrDie(leaderElectionCtx, leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      migrationsAsK8sJobConfig.leaseLockName,
				Namespace: migrationsAsK8sJobConfig.namespace,
			},
			Client: client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: leaseID,
			},
		},
		// IMPORTANT: you MUST ensure that any code you have that
		// is protected by the lease must terminate **before**
		// you call cancel. Otherwise, you could have a background
		// loop still running and another process could
		// get elected before your background loop finished, violating
		// the stated goal of the lease.
		ReleaseOnCancel: true,
		LeaseDuration:   60 * time.Second,
		RenewDeadline:   15 * time.Second,
		RetryPeriod:     5 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				cmd.Println("Starting controller loop...")
				cmd.SetContext(ctx)
				err = f(cmd, args)
				// close the channel so  that the  loop can be terminated
				close(ch)
			},
			OnStoppedLeading: func() {
				cmd.Printf("leader lost: %s\n", leaseID)
				leaderElectionCancel()
			},
			OnNewLeader: func(identity string) {
				// we're notified when new leader elected
				if identity == leaseID {
					// I just got the lock
					return
				}
				cmd.Printf("new leader elected: %s", identity)
			},
		},
	})

	return err
}

// generateMigrationJob generates a Job manifest
func generateMigrationJob(cmdName string) *batchv1.Job {
	if migrationsAsK8sJobConfig.image == "" {
		migrationsAsK8sJobConfig.image = "https://ghcr.io/smithy-security/smithy/smithyctl:latest"
	}

	migrationJob := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "smithy-migrations",
			Namespace: migrationsAsK8sJobConfig.namespace,
			Labels: labels.Set{
				"v1.smithy.smithy-security.com": "migrations",
				"generator":                     "smithyctl",
			},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Env:   getEnvVars(),
							Name:  "smithy-migrations",
							Image: migrationsAsK8sJobConfig.image,
							Args:  getCleanedUpArgs(cmdName, os.Args[1:]),
						},
					},
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: "smithy-migrations",
				},
			},
		},
	}

	return &migrationJob
}

func getEnvVars() []corev1.EnvVar {
	res := []corev1.EnvVar{{Name: "", Value: ""}}
	if migrationsCmdConfig.migratiosnPath != "" {
		res = []corev1.EnvVar{{Name: "SMITHYCTL_MIGRATIONS_PATH", Value: migrationsCmdConfig.migratiosnPath}}
	}
	return res
}
func getCleanedUpArgs(cmdName string, args []string) []string {
	cleanedUpPodArgs := []string{}
	argsToRemove := map[string]bool{
		"--as-k8s-job":  false,
		"--kubecontext": true,
		"--kubeconfig":  true,
		"--dry-run":     false,
		"--image":       true,
		"-i":            true,
	}
	var skip, skipNextArgToo bool
	for _, arg := range args {
		if skipNextArgToo {
			skipNextArgToo = false
			continue
		}
		if skipNextArgToo, skip = argsToRemove[arg]; !skip {
			cleanedUpPodArgs = append(cleanedUpPodArgs, arg)
		}
		if arg == cmdName {
			cleanedUpPodArgs = append(cleanedUpPodArgs, "--in-cluster")
		}
	}

	return cleanedUpPodArgs
}

func deployMigrationJob(cmd *cobra.Command, ssa string) error {
	migrationJob := generateMigrationJob(cmd.Name())
	if migrationsAsK8sJobConfig.dryRun {
		if err := manifests.BatchV1ObjEncoder.Encode(migrationJob, cmd.OutOrStdout()); err != nil {
			return errors.Errorf("could not marshal job manifest: %w", err)
		}
		return nil
	}

	if migrationsAsK8sJobConfig.kubeConfig == "" {
		migrationsAsK8sJobConfig.kubeConfig = path.Join(os.Getenv("HOME"), ".kube/config")
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", migrationsAsK8sJobConfig.kubeConfig)
	if err != nil {
		return errors.Errorf("%s: could not initialise K8s client config with: %w", migrationsAsK8sJobConfig.kubeConfig, err)
	}

	client, err := k8s.NewTypedClientForConfig(restCfg, ssa)
	if err != nil {
		return err
	}

	if err = client.Apply(cmd.Context(), migrationJob, migrationsAsK8sJobConfig.namespace, false); err != nil {
		return errors.Errorf("could not create migration job: %w", err)
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer func() { cancel() }()
	return jobPodLogWatcher(ctx, client, migrationsAsK8sJobConfig.namespace, migrationJob.Name, cmd.OutOrStdout())
}

func jobPodLogWatcher(ctx context.Context, client k8s.ClientInterface, namespace, name string, out io.Writer) error {
	var err error
	i64Ptr := func(i int64) *int64 { return &i }

	// get the job so that we can use it's label selector for subsequent queries
	deployedJob, err := client.
		BatchV1().
		Jobs(namespace).
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return errors.Errorf("%s/%s: could not get Job: %w", namespace, name, err)
	}

	// start a watcher to monitor the job status
	var watcher watch.Interface
	watcher, err = client.
		BatchV1().
		Jobs("smithy").
		Watch(ctx, metav1.ListOptions{
			LabelSelector:  metav1.FormatLabelSelector(deployedJob.Spec.Selector),
			TimeoutSeconds: i64Ptr(120),
			Watch:          true,
		})
	if err != nil {
		return errors.Errorf("could not watch status of migration job: %w", err)
	}
	defer watcher.Stop()

	// send a message if the Job itself is deleted
	jobDeleted := make(chan struct{})
	go func() {
		select {
		case event := <-watcher.ResultChan():
			if event.Type == watch.Deleted {
				err = errors.Errorf("%s/%s: job was deleted", namespace, name)
				close(jobDeleted)
			}
		case <-ctx.Done():
			return
		}
	}()

	podLogFollowingDone := make(chan struct{})
	// watch all pods related to the job
	go func() {
		defer func() { close(podLogFollowingDone) }()

		fieldSelectorSB := strings.Builder{}
		// remove from the list Pending pods or pods whose state is Unknown
		fieldSelectorSB.WriteString("status.phase!=Pending,status.phase!=Unknown")

		var podList *corev1.PodList
		if _, err = fmt.Fprintf(out, "watching pod logs for job: %s/%s\n", namespace, name); err != nil {
			return
		}

		// pods whose logs we have watched but don't know the exit code
		watchedPods := map[string]struct{}{}

		for {
			podList, err = client.
				CoreV1().
				Pods(deployedJob.Namespace).
				List(ctx, metav1.ListOptions{
					LabelSelector: metav1.FormatLabelSelector(deployedJob.Spec.Selector),
					FieldSelector: fieldSelectorSB.String(),
				})
			if err != nil {
				err = errors.Errorf("could not list pods generated for job %s/%s with labels %s: %w",
					deployedJob.Namespace, deployedJob.Name, metav1.FormatLabelSelector(deployedJob.Spec.Selector), err)
				return
			}

			var stream io.ReadCloser
			for _, pod := range podList.Items {
				if _, logsWatched := watchedPods[pod.Name]; logsWatched {
					if pod.Status.Phase == corev1.PodSucceeded {
						return
					} else if pod.Status.Phase == corev1.PodFailed {
						delete(watchedPods, pod.Name)
						fieldSelectorSB.WriteString(fmt.Sprintf(",metadata.name!=%s", pod.Name))
						continue
					}
				}

				// add pod to the map to check its status in the next iteration
				watchedPods[pod.Name] = struct{}{}

				stream, err = client.
					CoreV1().
					Pods(namespace).
					GetLogs(pod.Name, &corev1.PodLogOptions{Follow: true}).
					Stream(ctx)
				if err != nil {
					err = errors.Errorf("%s/%s: could not stream logs: %w", pod.Namespace, pod.Name, err)
					return
				}

				if _, err = fmt.Fprintf(out, "======= watching logs of pod %s/%s =======\n", pod.Namespace, pod.Name); err != nil {
					return
				}
				_, err = io.Copy(out, stream)
				sErr := stream.Close()
				if sErr != nil {
					if err != nil {
						err = errors.Errorf("%w: %w", sErr, err)
					} else {
						err = sErr
					}
				} else if err != nil {
					return
				}
				if _, err = fmt.Fprintf(out, "======= done watching logs of pod %s/%s =======\n", pod.Namespace, pod.Name); err != nil {
					return
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
				if len(podList.Items) == 0 {
					if _, err = fmt.Fprintf(out, "found no running/succeeded/failed pods, waiting for 3s to list again\n"); err != nil {
						return
					}
				}
			}
		}
	}()

	select {
	case <-jobDeleted:
	case <-podLogFollowingDone:
	}

	return err
}
