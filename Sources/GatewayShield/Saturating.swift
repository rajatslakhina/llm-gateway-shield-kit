/// Milliseconds on whatever clock the gateway is given. The gateway only ever
/// subtracts two readings, so the epoch does not matter; production should pass
/// a monotonic clock so a wall-clock step cannot refill budgets or skip TTLs.
public typealias Millis = Int

/// Non-trapping integer arithmetic.
///
/// Every number that reaches the gateway from a request or a policy goes through
/// these helpers instead of `+`, `*`, `/` and `%`, so no input can crash the
/// process. Ceilings are derived from `Int.max`, never a 64-bit literal, so the
/// same code is correct where `Int` is 32 bits wide.
public enum Saturating {
    public static func add(_ a: Int, _ b: Int) -> Int {
        let (r, overflow) = a.addingReportingOverflow(b)
        guard overflow else { return r }
        return b > 0 ? Int.max : Int.min
    }

    public static func subtract(_ a: Int, _ b: Int) -> Int {
        let (r, overflow) = a.subtractingReportingOverflow(b)
        guard overflow else { return r }
        return b < 0 ? Int.max : Int.min
    }

    public static func multiply(_ a: Int, _ b: Int) -> Int {
        let (r, overflow) = a.multipliedReportingOverflow(by: b)
        guard overflow else { return r }
        return (a < 0) == (b < 0) ? Int.max : Int.min
    }

    /// `nil` for a zero divisor; `Int.min / -1` saturates to `Int.max`.
    public static func divide(_ a: Int, _ b: Int) -> Int? {
        guard b != 0 else { return nil }
        let (r, overflow) = a.dividedReportingOverflow(by: b)
        return overflow ? Int.max : r
    }

    /// Ceiling division for `a >= 0, b > 0`; `nil` otherwise.
    public static func ceilDivide(_ a: Int, _ b: Int) -> Int? {
        guard a >= 0, b > 0 else { return nil }
        let q = a / b          // safe: b > 0 and a >= 0, so no Int.min / -1
        let r = a % b          // safe: same reasoning
        return r == 0 ? q : add(q, 1)
    }

    /// `value` clamped into `lower...upper` (`lower` wins if the range is inverted).
    public static func clamp(_ value: Int, _ lower: Int, _ upper: Int) -> Int {
        if value < lower { return lower }
        if value > upper { return max(lower, upper) }
        return value
    }
}
