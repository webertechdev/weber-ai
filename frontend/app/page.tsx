"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  BarChart3,
  Bell,
  Bot,
  Check,
  ChevronDown,
  FileText,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  Plus,
  Send,
  Settings2,
  ShieldCheck,
  Sparkles,
  Users,
  X,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

type Message = { role: "user" | "assistant"; content: string };
type Role = {
  id: number;
  name: string;
  department: string;
  description: string;
  scopes: string[];
  members: number;
  active: boolean;
  updated: string;
};

type View = "workspace" | "roles" | "reports";

const initialRoles: Role[] = [
  { id: 1, name: "ADMIN", department: "Executive office", description: "Full workspace governance and role administration.", scopes: ["All company data", "Role management", "Executive reports"], members: 3, active: true, updated: "Today, 09:42" },
  { id: 2, name: "Finance lead", department: "Finance", description: "Owns financial performance and forecasting analysis.", scopes: ["Revenue & margin", "Forecasting", "Board reports"], members: 6, active: true, updated: "Yesterday" },
  { id: 3, name: "People operations", department: "People & culture", description: "Monitors workforce health without access to payroll details.", scopes: ["Headcount", "Engagement", "Hiring"], members: 9, active: true, updated: "Oct 24, 2026" },
  { id: 4, name: "Operations analyst", department: "Operations", description: "Tracks service delivery, capacity and operational risk.", scopes: ["Delivery", "Capacity", "Risk register"], members: 12, active: false, updated: "Oct 18, 2026" },
];

const promptCards = [
  { label: "Executive brief", text: "Create a concise executive brief from this week’s company signals." },
  { label: "Revenue pulse", text: "Analyze revenue performance, margin movement, and the three drivers behind the change." },
  { label: "Risk scan", text: "Scan our allowed workspace data for emerging operational or commercial risks." },
];

export default function Home() {
  const [view, setView] = useState<View>("workspace");
  const [roles, setRoles] = useState<Role[]>(initialRoles);
  const [activeRole, setActiveRole] = useState<Role>(initialRoles[0]);
  const [roleMenuOpen, setRoleMenuOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [conversationId, setConversationId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const initializeChat = async () => {
      try {
        const savedId = localStorage.getItem("conversation_id");
        if (savedId) {
          setConversationId(Number(savedId));
          const response = await fetch(`${API_URL}/api/messages/${savedId}`);
          if (response.ok) setMessages(await response.json());
          return;
        }
        const response = await fetch(`${API_URL}/api/conversations`, { method: "POST" });
        if (!response.ok) return;
        const data = await response.json();
        localStorage.setItem("conversation_id", String(data.id));
        setConversationId(data.id);
      } catch (error) {
        console.warn("Chat service is not connected yet", error);
      }
    };
    initializeChat();
  }, []);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const sendMessage = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!message.trim() || !conversationId || loading) return;
    const currentMessage = message.trim();
    const updatedMessages = [...messages, { role: "user" as const, content: currentMessage }];
    setMessages(updatedMessages);
    setMessage("");
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: currentMessage, messages: updatedMessages, conversation_id: conversationId, role: activeRole.name, scopes: activeRole.scopes }),
      });
      if (!response.ok || !response.body) throw new Error("No response");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let aiResponse = "";
      setMessages((prev) => [...prev, { role: "assistant", content: "" }]);
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        aiResponse += decoder.decode(value, { stream: true });
        setMessages((prev) => [...prev.slice(0, -1), { role: "assistant", content: aiResponse }]);
      }
    } catch {
      setMessages((prev) => [...prev, { role: "assistant", content: "I’m ready to help, but the AI service is not connected in this environment yet. Your governed workspace and role context are ready." }]);
    } finally { setLoading(false); }
  };

  const createRole = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const name = String(form.get("name") || "New role");
    const department = String(form.get("department") || "General");
    const description = String(form.get("description") || "Role created by ADMIN.");
    const newRole: Role = { id: Date.now(), name, department, description, scopes: ["Workspace overview"], members: 0, active: true, updated: "Just now" };
    setRoles((current) => [...current, newRole]);
    setCreateOpen(false);
    event.currentTarget.reset();
  };

  return (
    <main className="app-shell">
      <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
        <div className="brand-lockup"><div className="brand-mark">W<span /></div><div><strong>WEBER AI</strong><small>Corporate intelligence</small></div></div>
        <div className="workspace-switcher"><span className="workspace-avatar">N</span><div><small>Workspace</small><b>Northstar Group</b></div><ChevronDown size={15} /></div>
        <nav className="main-nav">
          <p className="eyebrow">Command center</p>
          <button className={view === "workspace" ? "nav-item active" : "nav-item"} onClick={() => { setView("workspace"); setMobileNav(false); }}><LayoutDashboard size={18} />AI workspace</button>
          <button className={view === "reports" ? "nav-item active" : "nav-item"} onClick={() => { setView("reports"); setMobileNav(false); }}><BarChart3 size={18} />Business reports<span className="nav-count">4</span></button>
          <p className="eyebrow nav-section">Governance</p>
          <button className={view === "roles" ? "nav-item active" : "nav-item"} onClick={() => { setView("roles"); setMobileNav(false); }}><Users size={18} />Roles & access</button>
          <button className="nav-item"><ShieldCheck size={18} />Audit activity</button>
          <button className="nav-item"><Settings2 size={18} />Workspace settings</button>
        </nav>
        <div className="sidebar-footer"><div className="secure-line"><LockKeyhole size={14} />Your data boundary is active</div><div className="user-card"><span className="user-avatar">AM</span><div><b>Alex Morgan</b><small>Workspace admin</small></div><MoreDots /></div></div>
      </aside>

      <section className="content-area">
        <header className="topbar"><button className="mobile-menu" onClick={() => setMobileNav((open) => !open)}><Menu size={21} /></button><div className="breadcrumbs"><span>Northstar Group</span><span>/</span><b>{view === "workspace" ? "AI workspace" : view === "roles" ? "Roles & access" : "Business reports"}</b></div><div className="top-actions"><button className="icon-button"><Bell size={18} /><i /></button><div className="role-control"><button className="active-role" onClick={() => setRoleMenuOpen((open) => !open)}><span className="role-dot" />{activeRole.name}<ChevronDown size={15} /></button>{roleMenuOpen && <div className="role-menu">{roles.filter((role) => role.active).map((role) => <button key={role.id} onClick={() => { setActiveRole(role); setRoleMenuOpen(false); }}>{role.name}<small>{role.department}</small>{role.id === activeRole.id && <Check size={15} />}</button>)}</div>}</div></div></header>

        {view === "workspace" && <WorkspaceView activeRole={activeRole} messages={messages} message={message} setMessage={setMessage} sendMessage={sendMessage} loading={loading} bottomRef={bottomRef} onPrompt={(text) => setMessage(text)} />}
        {view === "reports" && <ReportsView onAsk={(text) => { setView("workspace"); setMessage(text); }} />}
        {view === "roles" && <RolesView roles={roles} onCreate={() => setCreateOpen(true)} />}
      </section>

      {createOpen && <div className="modal-backdrop" onClick={() => setCreateOpen(false)}><form className="role-drawer" onSubmit={createRole} onClick={(event) => event.stopPropagation()}><div className="drawer-header"><div><p className="eyebrow">ADMIN control</p><h2>Create a role</h2><p>Set a clear information boundary for a new teammate or function.</p></div><button type="button" className="icon-button" onClick={() => setCreateOpen(false)}><X size={18} /></button></div><label>Role name<input name="name" placeholder="e.g. Sales director" required /></label><label>Department<input name="department" placeholder="e.g. Commercial" required /></label><label>What should this role do?<textarea name="description" placeholder="Describe the decisions and work this role supports." rows={4} required /></label><div className="scope-editor"><div><b>Initial scope</b><span>Start narrow. ADMIN can expand this later.</span></div><div className="scope-option"><span className="scope-check"><Check size={13} /></span>Workspace overview</div><div className="scope-option muted"><span className="scope-check empty" />Revenue & margin</div><div className="scope-option muted"><span className="scope-check empty" />People & culture</div></div><button className="primary-button full" type="submit"><Plus size={17} />Create role</button></form></div>}
    </main>
  );
}

function WorkspaceView({ activeRole, messages, message, setMessage, sendMessage, loading, bottomRef, onPrompt }: { activeRole: Role; messages: Message[]; message: string; setMessage: (value: string) => void; sendMessage: (event?: FormEvent) => void; loading: boolean; bottomRef: React.RefObject<HTMLDivElement | null>; onPrompt: (value: string) => void }) {
  return <div className="page-wrap workspace-page"><div className="page-heading"><div><p className="eyebrow">{activeRole.name} view <span className="status-pill"><span />Governed</span></p><h1>Make the next decision obvious.</h1><p className="heading-copy">Your corporate AI partner for analysis, reporting, and the work between the numbers.</p></div><button className="secondary-button"><FileText size={16} />View briefing history</button></div><div className="workspace-grid"><section className="chat-card"><div className="chat-header"><div className="ai-id"><span className="ai-orb"><Sparkles size={17} /></span><div><b>Weber intelligence</b><span>Context-aware corporate analysis</span></div></div><span className="context-badge"><LockKeyhole size={13} />{activeRole.scopes.length} scopes active</span></div><div className="messages">{messages.length === 0 ? <div className="welcome-state"><span className="welcome-icon"><Bot size={24} /></span><h2>Good morning, Alex.</h2><p>Ask me to connect the dots across your permitted workspace data. I’ll keep the analysis bounded to <b>{activeRole.name}</b>.</p><div className="prompt-grid">{promptCards.map((prompt) => <button key={prompt.label} onClick={() => onPrompt(prompt.text)}><span>{prompt.label}</span><ArrowUpRight size={16} /></button>)}</div></div> : messages.map((msg, index) => <div className={`message-row ${msg.role}`} key={index}><span className="message-avatar">{msg.role === "assistant" ? <Sparkles size={14} /> : "AM"}</span><div className="message-bubble"><small>{msg.role === "assistant" ? "WEBER INTELLIGENCE" : "YOU"}</small><ReactMarkdown remarkPlugins={[remarkGfm]}>{msg.content}</ReactMarkdown></div></div>)}{loading && <div className="message-row assistant"><span className="message-avatar"><Sparkles size={14} /></span><div className="message-bubble thinking"><small>WEBER INTELLIGENCE</small><span className="thinking-dots"><i /><i /><i /></span></div></div>}<div ref={bottomRef} /></div><form className="composer" onSubmit={sendMessage}><textarea value={message} onChange={(event) => setMessage(event.target.value)} placeholder={`Ask as ${activeRole.name}...`} rows={1} disabled={loading} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); sendMessage(); } }} /><button type="submit" className="send-button" disabled={loading || !message.trim()}><Send size={17} /></button></form><div className="composer-note"><LockKeyhole size={13} />Responses are limited to your role’s active data scopes.</div></section><aside className="context-rail"><div className="rail-card"><div className="rail-title"><span>Workspace signal</span><Activity size={17} /></div><div className="signal-number">+12.8<span>%</span></div><p>Revenue momentum is up against the previous 30-day period.</p><div className="signal-foot"><span className="positive">↑ 4.2 pts</span><span>Last updated 18m ago</span></div></div><div className="rail-card"><div className="rail-title"><span>Active boundary</span><ShieldCheck size={17} /></div><div className="boundary-title">{activeRole.name}<span>ACTIVE</span></div><p>{activeRole.description}</p><div className="scope-list">{activeRole.scopes.map((scope) => <span key={scope}>{scope}</span>)}</div><button className="text-button">Review permissions <ArrowUpRight size={14} /></button></div><div className="rail-card next-card"><div className="rail-title"><span>Next best action</span><Sparkles size={17} /></div><p>Turn the latest signal into a shareable leadership brief.</p><button className="secondary-button small" onClick={() => onPrompt("Turn the latest workspace signals into a one-page leadership brief with decisions and owners.")}><FileText size={14} />Draft brief</button></div></aside></div></div>;
}

function ReportsView({ onAsk }: { onAsk: (text: string) => void }) { return <div className="page-wrap"><div className="page-heading"><div><p className="eyebrow">Decision support</p><h1>Business reports</h1><p className="heading-copy">Reusable intelligence for the conversations that move the business forward.</p></div><button className="primary-button" onClick={() => onAsk("Create an executive report from the latest business signals.")}><Sparkles size={16} />Run new analysis</button></div><div className="report-layout"><div className="report-feature"><div className="report-label"><span className="report-icon"><BarChart3 size={17} /></span><span>Weekly executive pulse</span><span className="report-status">Ready to share</span></div><h2>Growth is healthy, but delivery capacity is the constraint to watch.</h2><p>Weber connected 24 permitted signals across revenue, delivery, and customer operations to surface three decision points for this week.</p><div className="report-metrics"><div><b>+12.8%</b><span>Revenue momentum</span></div><div><b>84%</b><span>Delivery capacity</span></div><div><b>3</b><span>Priority signals</span></div></div><button className="secondary-button" onClick={() => onAsk("Walk me through the weekly executive pulse and recommend the top decision.")}>Ask Weber about this report <ArrowUpRight size={15} /></button></div><div className="report-list"><ReportRow title="Revenue & margin review" meta="Finance lead · 7 min read" color="orange" onAsk={onAsk} /><ReportRow title="Workforce health snapshot" meta="People operations · 4 min read" color="green" onAsk={onAsk} /><ReportRow title="Operational risk scan" meta="Operations analyst · 5 min read" color="blue" onAsk={onAsk} /></div></div></div> }
function ReportRow({ title, meta, color, onAsk }: { title: string; meta: string; color: string; onAsk: (text: string) => void }) { return <button className="report-row" onClick={() => onAsk(`Summarize the ${title} report and explain the most important implication.`)}><span className={`report-dot ${color}`} /><span><b>{title}</b><small>{meta}</small></span><ArrowUpRight size={16} /></button>; }
function RolesView({ roles, onCreate }: { roles: Role[]; onCreate: () => void }) { return <div className="page-wrap"><div className="page-heading"><div><p className="eyebrow">ADMIN control plane</p><h1>Roles & access</h1><p className="heading-copy">Design the information boundaries that let every team move faster, safely.</p></div><button className="primary-button" onClick={onCreate}><Plus size={17} />Create role</button></div><div className="roles-summary"><div><span>Total roles</span><b>{roles.length}</b></div><div><span>Active members</span><b>{roles.reduce((sum, role) => sum + role.members, 0)}</b></div><div><span>Protected scopes</span><b>18</b></div><div><span>Governance health</span><b className="health"><span />Good</b></div></div><div className="roles-panel"><div className="panel-header"><div><h2>Workspace roles</h2><p>Every role receives a deliberate, reviewable boundary.</p></div><button className="filter-button">All roles <ChevronDown size={14} /></button></div><div className="role-table"><div className="role-table-head"><span>Role</span><span>Access scopes</span><span>Members</span><span>Activity</span><span>Status</span></div>{roles.map((role) => <div className="role-table-row" key={role.id}><div className="role-name"><span className="role-avatar">{role.name.slice(0, 1)}</span><span><b>{role.name}</b><small>{role.department}</small></span></div><div className="table-scopes">{role.scopes.slice(0, 2).map((scope) => <span key={scope}>{scope}</span>)}{role.scopes.length > 2 && <span>+{role.scopes.length - 2}</span>}</div><span className="muted-value">{role.members} {role.members === 1 ? "member" : "members"}</span><span className="muted-value">{role.updated}</span><span className={role.active ? "table-status active" : "table-status"}><i />{role.active ? "Active" : "Paused"}</span></div>)}</div></div></div> }
function MoreDots() { return <span className="more-dots">•••</span>; }
