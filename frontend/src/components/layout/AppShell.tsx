import { ReactNode } from "react";
import TopNav from "./TopNav";
import NodeNetwork from "../ui/NodeNetwork";

export default function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen relative bg-circuit bg-radial-glow">
      <TopNav />
      {/* Subtle animated node mesh behind content */}
      <NodeNetwork
        className="opacity-40"
        nodeCount={30}
        connectionDistance={180}
        nodeColor="rgba(0, 212, 255, 0.2)"
        lineColor="rgba(0, 212, 255, 0.04)"
        nodeSize={1}
      />
      <main className="relative pt-4 pb-8 px-6 max-w-[1400px] mx-auto">
        {children}
      </main>
    </div>
  );
}
