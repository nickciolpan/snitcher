class CliSnitch < Formula
  desc "Terminal-based network connection monitor and firewall manager for macOS"
  homepage "https://github.com/nickciolpan/snitcher"
  url "https://github.com/nickciolpan/snitcher/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "7747153ba03f2e678b12a36f2875ed450b8d0219c02edf63abf77adba9129d8b"
  license "MIT"
  head "https://github.com/nickciolpan/snitcher.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/cli-snitch"
  end

  def caveats
    <<~EOS
      CLI Snitch requires root privileges for network monitoring and firewall management.

      Quick start:
        sudo cli-snitch watch

      Other commands:
        cli-snitch list-rules
        cli-snitch history
        cli-snitch system-status
        sudo cli-snitch daemon install

      Documentation: https://github.com/nickciolpan/snitcher#readme
    EOS
  end

  test do
    assert_match "CLI Snitch", shell_output("#{bin}/cli-snitch --help")
    assert_match "watch", shell_output("#{bin}/cli-snitch --help")
    assert_match "list-rules", shell_output("#{bin}/cli-snitch --help")
    assert_match "history", shell_output("#{bin}/cli-snitch --help")
    assert_match "daemon", shell_output("#{bin}/cli-snitch --help")

    assert_match(/rules|No rules/, shell_output("#{bin}/cli-snitch list-rules 2>&1"))
  end
end
