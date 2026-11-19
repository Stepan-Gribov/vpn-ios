import Foundation

struct ConnectionFallbackPlan {
    struct Candidate: Equatable {
        let profileID: String
        let delayMilliseconds: Int?
        let failed: Bool
        let automaticEligible: Bool
    }

    private let candidates: [Candidate]
    private(set) var position = 0
    private(set) var attemptNumber = 1

    var count: Int { candidates.count }
    var orderedProfileIDs: [String] { candidates.map(\.profileID) }
    var current: Candidate { candidates[position] }

    mutating func advance() -> Candidate? {
        for nextPosition in candidates.indices.dropFirst(position + 1) {
            let candidate = candidates[nextPosition]
            position = nextPosition
            attemptNumber += 1
            return candidate
        }
        return nil
    }

    static func fastest(_ profiles: [VPNProfile], excludingVKTurn: Bool = false) -> ConnectionFallbackPlan? {
        let values = profiles.enumerated()
            .filter { !excludingVKTurn || !$0.element.isTURN || $0.element.isDNS }
            .map { index, profile in
                (
                    index,
                    Candidate(
                        profileID: profile.id,
                        delayMilliseconds: profile.latencyMilliseconds,
                        failed: profile.lastError != nil,
                        automaticEligible: true
                    )
                )
            }
            .filter { $0.1.automaticEligible }
            .sorted { lhs, rhs in
                let leftRank = rank(lhs.1)
                let rightRank = rank(rhs.1)
                if leftRank != rightRank { return leftRank < rightRank }
                let leftDelay = leftRank == 0 ? (lhs.1.delayMilliseconds ?? .max) : .max
                let rightDelay = rightRank == 0 ? (rhs.1.delayMilliseconds ?? .max) : .max
                if leftDelay != rightDelay { return leftDelay < rightDelay }
                return lhs.0 < rhs.0
            }
            .map(\.1)

        var seen = Set<String>()
        let unique = values.filter { seen.insert($0.profileID).inserted }
        return unique.isEmpty ? nil : ConnectionFallbackPlan(candidates: unique)
    }

    private static func rank(_ candidate: Candidate) -> Int {
        if candidate.failed { return 2 }
        if let delay = candidate.delayMilliseconds, delay > 0 { return 0 }
        return 1
    }
}
