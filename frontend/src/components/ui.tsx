import React from "react";

export function Card({ title, subtitle, right, children, className }: {
  title?: string;
  subtitle?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`card ${className ?? ""}`.trim()}>
      {(title || subtitle || right) ? (
        <div style={{ display: "flex", gap: 12, alignItems: "start" }}>
          <div style={{ flex: 1 }}>
            {title ? <h1>{title}</h1> : null}
            {subtitle ? <p style={{ marginTop: 6 }}>{subtitle}</p> : null}
          </div>
          {right ? <div>{right}</div> : null}
        </div>
      ) : null}
      <div style={{ marginTop: title || subtitle ? 12 : 0 }}>{children}</div>
    </div>
  );
}

export function Alert({ kind, children }: { kind: "error" | "ok" | "info"; children: React.ReactNode }) {
  const cls = kind === "error" ? "alert error" : kind === "ok" ? "alert ok" : "alert";
  return <div className={cls}>{children}</div>;
}

export function Pill({ kind, children }: { kind?: "ok" | "warn" | "danger"; children: React.ReactNode }) {
  const cls = kind ? `pill ${kind}` : "pill";
  return <span className={cls}>{children}</span>;
}

export function Button(props: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" }) {
  const { variant, className, ...rest } = props;
  const v = variant === "primary" ? "primary" : variant === "ghost" ? "ghost" : "";
  return <button className={`btn ${v} ${className ?? ""}`.trim()} {...rest} />;
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return <span className="kbd">{children}</span>;
}
export function Mono({ children }: { children: React.ReactNode }) {
  return <span className="mono">{children}</span>;
}
export function SkeletonRow() {
  return <div className="skel" />;
}
