import SwiftUI
import WebKit

struct LocalCaptchaView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var reloadID = UUID()
    var url = URL(string: "http://localhost:8765/")!

    var body: some View {
        NavigationStack {
            LocalhostWebView(url: url)
                .id(reloadID)
                .navigationTitle("VK verification")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Refresh") { reloadID = UUID() }
                    }
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Done") { dismiss() }
                    }
                }
        }
    }
}

struct LocalhostWebView: UIViewRepresentable {
    let url: URL

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        if #available(iOS 17.0, *) { configuration.preferences.inactiveSchedulingPolicy = .none }
        let view = WKWebView(frame: .zero, configuration: configuration)
        view.navigationDelegate = context.coordinator
        context.coordinator.webView = view
        if Self.isLocalChallenge(url) {
            view.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15))
        }
        return view
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    static func dismantleUIView(_ uiView: WKWebView, coordinator: Coordinator) {
        coordinator.stop()
        uiView.stopLoading()
        uiView.navigationDelegate = nil
        uiView.configuration.userContentController.removeAllUserScripts()
    }

    func makeCoordinator() -> Coordinator { Coordinator(url: url) }

    static func isLocalChallenge(_ url: URL) -> Bool {
        url.scheme == "http" && ["localhost", "127.0.0.1", "[::1]"].contains(url.host?.lowercased() ?? "") && url.port == 8765
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        let url: URL
        weak var webView: WKWebView?
        private var retryScheduled = false
        private var retriesRemaining = 120
        private var retryWork: DispatchWorkItem?
        private var stopped = false
        init(url: URL) { self.url = url }

        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = action.request.url, LocalhostWebView.isLocalChallenge(url) else { decisionHandler(.cancel); return }
            decisionHandler(.allow)
        }

        func webViewWebContentProcessDidTerminate(_ webView: WKWebView) { scheduleRetry() }

        func stop() {
            stopped = true
            retryWork?.cancel()
            retryWork = nil
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation?, withError error: Error) {
            scheduleRetry()
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation?, withError error: Error) {
            scheduleRetry()
        }

        private func scheduleRetry() {
            guard !stopped, LocalhostWebView.isLocalChallenge(url), !retryScheduled, retriesRemaining > 0 else { return }
            retryScheduled = true
            retriesRemaining -= 1
            let work = DispatchWorkItem { [weak self] in
                guard let self, !self.stopped, let webView = self.webView else { return }
                self.retryScheduled = false
                webView.load(URLRequest(url: self.url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15))
            }
            retryWork = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: work)
        }
    }
}
