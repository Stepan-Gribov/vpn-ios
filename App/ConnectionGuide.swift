import SwiftUI

private let ink = Color(red: 0.08, green: 0.12, blue: 0.22)
private let muted = Color(red: 0.44, green: 0.48, blue: 0.55)
private let blue = Color(red: 0.09, green: 0.51, blue: 0.97)

struct ConnectionGuide: View {
    @Environment(\.dismiss) private var dismiss
    @State private var page = 0
    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                TabView(selection: $page) {
                    pageContent { overview }.tag(0)
                    pageContent { restore }.tag(1)
                    pageContent { amnezia }.tag(2)
                    pageContent { manual }.tag(3)
                    pageContent { split }.tag(4)
                }
                .tabViewStyle(.page(indexDisplayMode: .never))
                .accessibilityIdentifier("guidePages")
                Divider().overlay(Color.gray.opacity(0.06))
                HStack {
                    Button {
                        withAnimation { page = max(0, page - 1) }
                    } label: { Label("Back", systemImage: "chevron.left") }
                    .accessibilityIdentifier("guideBack").disabled(page == 0).frame(width: 76, alignment: .leading)
                    Spacer(minLength: 8)
                    VStack(spacing: 6) {
                        HStack(spacing: 7) {
                            ForEach(0..<5, id: \.self) { index in
                                Circle().fill(index == page ? blue : Color.gray.opacity(0.25)).frame(width: 6, height: 6)
                            }
                        }
                        Text("\(page + 1) of 5").accessibilityIdentifier("guidePageIndicator").font(.caption2).foregroundStyle(muted)
                    }
                    Spacer(minLength: 8)
                    Button {
                        if page == 4 { dismiss() }
                        else { withAnimation { page += 1 } }
                    } label: {
                        HStack(spacing: 5) {
                            Text(page == 4 ? "Done" : "Next")
                            if page < 4 { Image(systemName: "chevron.right") }
                        }
                    }.accessibilityIdentifier("guideNext").frame(width: 76, alignment: .trailing)
                }.font(.subheadline.weight(.semibold)).padding(.horizontal, 20).padding(.top, 14).padding(.bottom, 12)
            }.background(Color.white)
            .navigationTitle("Connection guide").navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Color.white, for: .navigationBar).toolbarBackground(.visible, for: .navigationBar)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Close") { dismiss() }.accessibilityIdentifier("closeConnectionGuide") } }
        }.presentationDetents([.large]).presentationDragIndicator(.visible)
    }

    private func pageContent<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            content()
            Spacer(minLength: 0)
        }.padding(.horizontal, 20).padding(.top, 14).padding(.bottom, 12)
            .frame(maxWidth: 620).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    private var overview: some View {
        VStack(alignment: .leading, spacing: 12) {
            heading(0, "Choose a connection")
            route("Amnezia", icon: "shield.lefthalf.filled", good: "Fast, including on mobile data. Good for browsing and video.", limit: "May be blocked by strict network allowlists.")
            route("TURN proxy", icon: "phone", good: "Good speed under heavy restrictions, while VK is reachable.", limit: "May drop while moving. Auto-recovery reconnects; occasionally needs attention.")
            route("DNS tunnel", icon: "network", good: "Can work with strict allowlists. Useful for Telegram messages.", limit: "Very slow. Not suitable for calls or video.")
            VStack(alignment: .leading, spacing: 6) {
                Label("Which one should I use?", systemImage: "lightbulb").font(.subheadline.weight(.semibold)).foregroundStyle(blue)
                Text("Amnezia for speed; TURN when VK is available; DNS for messages under strict restrictions.").font(.subheadline).foregroundStyle(ink)
            }.padding(14).frame(maxWidth: .infinity, alignment: .leading).background(blue.opacity(0.07), in: RoundedRectangle(cornerRadius: 16))
        }
    }
    private var restore: some View {
        VStack(alignment: .leading, spacing: 12) {
            heading(1, "Restore a full setup")
            Text("Received a TnDtun settings file? Start here.").font(.subheadline).foregroundStyle(muted)
            VStack(alignment: .leading, spacing: 14) {
                instruction("Save the .json file in Files.", symbol: "doc")
                instruction("Open Settings → Transfer → Import from file.", symbol: "square.and.arrow.down")
                instruction("Choose the file, review it, then tap Replace and import.", symbol: "checkmark.circle")
                Divider()
                Text("All profiles, keys, DNS settings and split rules are restored. Import replaces the profiles and settings already on this device.").font(.footnote).foregroundStyle(muted)
                Label("Then choose a profile and tap play to connect.", systemImage: "play.fill").font(.subheadline.weight(.medium)).foregroundStyle(blue)
            }.guideCardStyle()
            Text("Your backup contains connection keys. Keep it private.").font(.footnote).foregroundStyle(muted)
        }
    }
    private var amnezia: some View {
        VStack(alignment: .leading, spacing: 12) {
            heading(2, "Add an Amnezia profile")
            VStack(alignment: .leading, spacing: 14) {
                instruction("Select the Amnezia tab and tap +.", symbol: "plus.circle")
                instruction("Paste the complete vpn:// key shared from Amnezia.", symbol: "doc.on.clipboard")
                instruction("Save → select the profile → connect.", symbol: "play.fill")
                Divider()
                Text("Allow iOS to add a VPN configuration if asked. If your backup already contains this profile, you can connect straight away.").font(.footnote).foregroundStyle(muted)
            }.guideCardStyle()
        }
    }
    private var manual: some View {
        VStack(alignment: .leading, spacing: 12) {
            heading(3, "Set up TURN and DNS")
            optionalNote
            VStack(alignment: .leading, spacing: 10) {
                Label("TURN proxy", systemImage: "phone").font(.headline).foregroundStyle(ink)
                Text("TURN proxy → +. Paste JSON, or enter:").font(.subheadline)
                Text("VK call link · server address · UUID VLESS · transport key").font(.subheadline.weight(.medium)).foregroundStyle(ink)
                Text("UUID is required. Use the server’s transport key, or leave it blank if wrapping is off.").font(.footnote).foregroundStyle(muted)
                Text("Save → select the profile → connect.").font(.subheadline).foregroundStyle(blue)
            }.guideCardStyle()
            VStack(alignment: .leading, spacing: 10) {
                Label("DNS tunnel", systemImage: "network").font(.headline).foregroundStyle(ink)
                Text("DNS tunnel → +. Paste JSON, or enter the tunnel address, public key and server mode (SOCKS5/SSH). Save.").font(.subheadline)
                Divider()
                Text("Mobile data").font(.subheadline.weight(.semibold))
                Text("Enable Auto-detect DNS before connecting to use your current network’s DNS.").font(.footnote).foregroundStyle(muted)
                Text("Wi-Fi").font(.subheadline.weight(.semibold))
                Text("For a fixed Wi-Fi DNS, enable Separate DNS for Wi-Fi (for example, 8.8.8.8).").font(.footnote).foregroundStyle(muted)
            }.guideCardStyle()
        }
    }
    private var split: some View {
        VStack(alignment: .leading, spacing: 12) {
            heading(4, "Split tunneling")
            optionalNote
            Text("Settings → Split tunneling").font(.subheadline.weight(.medium)).foregroundStyle(blue)
            Text("Works with all three connection types. Choose one mode:").font(.subheadline).foregroundStyle(muted)
            VStack(alignment: .leading, spacing: 8) {
                Text("Bypass selected addresses").font(.subheadline.weight(.semibold))
                Text("Listed addresses connect directly. Everything else uses the VPN.").font(.subheadline).foregroundStyle(muted)
            }.guideCardStyle()
            VStack(alignment: .leading, spacing: 8) {
                Text("Tunnel selected addresses only").font(.subheadline.weight(.semibold))
                Text("Only listed addresses use the VPN. Everything else connects directly.").font(.subheadline).foregroundStyle(muted)
            }.guideCardStyle()
            VStack(alignment: .leading, spacing: 12) {
                instruction("Add a domain, IP or CIDR manually, or use Choose JSON file to load an address list.", symbol: "plus.circle")
                instruction("Tap Save. An active tunnel reconnects to apply changed rules.", symbol: "checkmark.circle")
                Divider()
                Text("Each mode keeps its own list. Only one mode can be active. Off sends all traffic through the selected VPN.").font(.footnote).foregroundStyle(muted)
            }.guideCardStyle()
        }
    }
    private var optionalNote: some View {
        Label("Optional — skip if included in your backup", systemImage: "checkmark.circle")
            .font(.footnote.weight(.medium)).foregroundStyle(blue)
    }
    private func heading(_ step: Int, _ title: String) -> some View {
        HStack(spacing: 10) {
            Text(String(step)).font(.subheadline.weight(.semibold)).foregroundStyle(.white).frame(width: 28, height: 28).background(blue, in: Circle())
            Text(title).font(.title3.weight(.semibold)).foregroundStyle(ink)
        }
    }
    private func route(_ title: String, icon: String, good: String, limit: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: icon).foregroundStyle(blue).frame(width: 34, height: 34).background(blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                Text(title).font(.headline)
            }
            Text(good).font(.subheadline).foregroundStyle(ink).fixedSize(horizontal: false, vertical: true)
            Text(limit).font(.footnote).foregroundStyle(muted).fixedSize(horizontal: false, vertical: true)
        }.guideCardStyle()
    }
    private func instruction(_ text: String, symbol: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol).foregroundStyle(blue).frame(width: 20)
            Text(text).font(.subheadline).foregroundStyle(ink).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

extension View {
    fileprivate func guideCardStyle() -> some View {
        padding(14).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.white, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(red: 0.89, green: 0.92, blue: 0.95), lineWidth: 1))
    }
}
