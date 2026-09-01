import type { PermissionStatus } from "./tauri";
import { api } from "./tauri";
import { Btn } from "./ui";

export function Onboarding({ perms, blocking, restarting, onSkip, onContinue }: {
  perms: PermissionStatus[];
  blocking: PermissionStatus[];
  restarting: boolean;
  onSkip: () => void;
  onContinue: () => void;
}) {
  const missing = blocking.length;
  return (
    <div className="onboard">
      <div className="onboard-card">
        <span className="onboard-mark" />
        <h1>eve needs two clicks</h1>
        <p className="onboard-lead">
          macOS keeps your files behind a switch that only you can flip. eve will
          open the exact page — you turn it on, and that is the setup.
        </p>

        <div style={{ textAlign: "left" }}>
          {perms.map((p) => {
            const blocks = p.required && p.state === "denied";
            return (
              <div key={p.permission} className={`perm is-${p.state}`}>
                <span className="perm-ic">
                  {p.state === "granted" ? "✓" : p.state === "denied" ? "▲" : "?"}
                </span>
                <div style={{ minWidth: 0 }}>
                  <div className="perm-title">{p.title}{p.required ? "" : " · optional"}</div>
                  <div className="perm-note">
                    {p.state === "granted"
                      ? "Granted."
                      : p.state === "unknown"
                        ? `macOS will ask the first time it is needed. ${p.what_breaks}`
                        : p.what_breaks}
                  </div>
                </div>
                {p.state !== "granted" && (
                  <Btn kind={blocks ? "primary" : "ghost"} size={blocks ? undefined : "sm"}
                       onClick={() => api.openPrivacySettings(p.permission)}>
                    {blocks ? "Open Settings" : "Grant early"}
                  </Btn>
                )}
              </div>
            );
          })}
        </div>

        <div className="onboard-actions">
          <Btn kind="primary" disabled={missing > 0 || restarting} onClick={onContinue}>
            {restarting ? "Restarting eve…" : missing > 0 ? "Waiting for permission…" : "Continue"}
          </Btn>
          <Btn onClick={onSkip}>Continue without it</Btn>
        </div>
        <p className="onboard-foot">
          {missing > 0
            ? `Look for “${blocking[0]?.look_for ?? "eve"}” in the list that opens.`
            : "eve needs to restart before macOS will let it use this."}
        </p>
      </div>
    </div>
  );
}
