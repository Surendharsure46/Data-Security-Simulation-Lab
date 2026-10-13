import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { ApiError, errorText } from "../api";
import type { PolicyDefinition, TraceEntry } from "../types";
import { PolicyEditor, emptyDefinition } from "./PolicyEditor";
import { TraceList } from "./Trace";
import { LabelBadge, Provenance, Status } from "./ui";

function Harness({ onChange }: { onChange: (d: PolicyDefinition) => void }) {
  const [d, setD] = useState(emptyDefinition());
  return <PolicyEditor value={d} onChange={(n) => { setD(n); onChange(n); }} />;
}

describe("PolicyEditor", () => {
  it("adds conditions, nested groups and exceptions to the structured definition", () => {
    let latest = emptyDefinition();
    render(<Harness onChange={(d) => (latest = d)} />);
    fireEvent.click(screen.getAllByRole("button", { name: "+ Condition" })[0]);
    expect(latest.conditions.conditions).toHaveLength(2);
    expect(latest.conditions.conditions[1]).toEqual({ field: "content.label", op: "label_at_least", value: "confidential" });
    fireEvent.click(screen.getAllByRole("button", { name: "+ Nested group" })[0]);
    expect((latest.conditions.conditions[2] as any).match).toBe("any");
    fireEvent.click(screen.getByRole("button", { name: "+ Exception" }));
    expect(latest.exceptions).toHaveLength(1);
    expect(latest.exceptions[0].outcome).toBe("ALLOW");
  });

  it("parses list values for list operators on blur", () => {
    let latest = emptyDefinition();
    render(<Harness onChange={(d) => (latest = d)} />);
    fireEvent.change(screen.getAllByLabelText("Operator")[0], { target: { value: "in" } });
    const input = screen.getAllByLabelText("Value")[0];
    fireEvent.blur(input, { target: { value: "dst-a, dst-b" } });
    expect((latest.conditions.conditions[0] as any).value).toEqual(["dst-a", "dst-b"]);
  });

  it("restricts DETECTION policies to MONITOR", () => {
    let latest = emptyDefinition();
    render(<Harness onChange={(d) => (latest = d)} />);
    fireEvent.change(screen.getByLabelText("Kind"), { target: { value: "DETECTION" } });
    expect(latest.outcome).toBe("MONITOR");
    expect(screen.getByLabelText(/^Outcome/).querySelectorAll("option")).toHaveLength(1);
  });
});

describe("TraceList", () => {
  it("shows the decision and each condition with its actual value", () => {
    const entry: TraceEntry = {
      policy_key: "POL-X", policy_version: 2, name: "Test", kind: "DLP", status: "ENABLED", priority: 1, configured_outcome: "BLOCK",
      severity: "HIGH", matched: false, exception: null, effective_outcome: null, alert: false, explanation: "",
      condition_trace: { group: "all", result: false, children: [{ field: "content.label", op: "label_at_least", value: "confidential", actual: null, missing: true, result: false }] },
    };
    render(<TraceList entries={[entry]} decision={{ outcome: "ALLOW", decisive_policy: null, decisive_version: null, reason: "No enabled policy matched" }} />);
    expect(screen.getByText(/Decision: ALLOW/)).toBeInTheDocument();
    expect(screen.getByText(/actual MISSING/)).toBeInTheDocument();
    expect(screen.getByText("no match")).toBeInTheDocument();
  });
});

describe("accessible status indicators", () => {
  it("always render text, not colour alone", () => {
    render(<><Status value="ALLOWED_WITH_WARNING" /><LabelBadge label={null} /><Provenance mode="REAL_LAB" /><Provenance mode="SIMULATED" /></>);
    expect(screen.getByText("ALLOWED WITH WARNING")).toBeInTheDocument();
    expect(screen.getByText("UNLABELED")).toBeInTheDocument();
    expect(screen.getByText("REAL LAB")).toBeInTheDocument();
    expect(screen.getByText("SIMULATED")).toBeInTheDocument();
  });
});

describe("errorText", () => {
  it("includes field-level validation details", () => {
    expect(errorText(new ApiError(422, "Invalid input", [{ field: "password", message: "too short" }]))).toBe("Invalid input: password — too short");
    expect(errorText(new Error("boom"))).toBe("boom");
  });
});
