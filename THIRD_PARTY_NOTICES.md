# Third-party notices

The project source is distributed under the [Apache-2.0 license](LICENSE). That grant does not relicense third-party components.

- **Marked 17.0.5** is embedded in the binary's browser assets. It is MIT licensed; the original copyright and license are retained in [LICENSE.marked.txt](https://github.com/bishoku/jvmdiag/blob/main/internal/server/assets/js/LICENSE.marked.txt), also included as `LICENSE.marked.txt` in release archives.
- **Go standard library and runtime** are included in compiled executables under Go's BSD-style license. See the included `LICENSE-Go.txt` and [the Go license](https://go.dev/LICENSE). Build metadata identifies the compiler version. There are currently no third-party Go modules.
- **Temurin OpenJDK** and the operating-system packages belong to their respective container base images. OpenJDK is distributed under GPLv2 with the Classpath Exception and additional component notices; retain the JDK's `legal` directory and base-image licenses when redistributing diagnostic images. See [Adoptium license information](https://adoptium.net/about/).
- **Alpine Linux** server-image packages retain their individual package licenses. The project's Apache-2.0 license does not apply to their source code.
- **Eclipse MAT** is an optional external tool, not included in release binaries or images. Its distribution is governed by its own licenses. Installing it from the application's settings retrieves a separate distribution.
- **Playwright** and **kind** are development/test tools, not embedded in the release executable. Their upstream licenses apply when installing them.

`tests/corpus/jvm-v1` contains normalized synthetic diagnostic outputs, not production data or redistributed JDK executables. Exact workload/capture source and provenance are archived with the dataset. Review privacy and provenance before contributing additional captures.
