# Weber AI corporate workspace plan

## Implementation

Preserve the existing Next.js chat and FastAPI streaming flow, then add a corporate workspace shell around it. The frontend will provide three connected surfaces: AI Workspace for role-aware chat, Roles & access for ADMIN-managed role creation and permissions, and Reports for business intelligence outputs. Role state is currently client-side for a fast, usable prototype and is structured so it can move to API persistence; the backend adds role-aware request fields and a small roles API backed by SQLite.

The primary role is ADMIN. ADMIN can create general-purpose corporate roles, assign a department, description, and access scopes, and see whether a role is active. The assistant system prompt receives the active role and allowed scopes so the model is instructed not to disclose information outside that role. Non-admin experiences can use the same shell while only seeing allowed workspace data.

Project structure:
- `frontend/app/page.tsx`: client workspace shell, role switcher, chat, role-management drawer, reports view.
- `frontend/app/globals.css`: visual system and responsive layout.
- `frontend/public/manus-routes.json`: route manifest for the single-page workspace.
- `backend/models.py`: Conversation, ChatMessage, CorporateRole, and RoleScope persistence models.
- `backend/main.py`: existing chat endpoints plus role CRUD and role-aware prompting.

## Design

### Style options
- Editorial command center: 0.06 probability
- Quiet fintech operations desk: 0.08 probability
- **Chosen — Warm enterprise intelligence console: 0.05 probability**

### Design movement
Warm enterprise intelligence console: Linear-like precision softened by a paper-white canvas, ink-black navigation, and a single vermilion signal color.

### Core principles
- Make authority visible: active role, scopes, and governance status are always in view.
- Make the next useful action obvious: prompts, reports, and create-role actions stay close to the main work surface.
- Prefer calm density over decoration: information-rich cards, generous rhythm, minimal gradients.
- Keep AI accountable: cite workspace context and show when a response is bounded by permissions.

### Color philosophy
Ink (#171717) carries trust and focus, parchment (#f6f5f1) gives the workspace a breathable paper-like base, vermilion (#ee6c4d) marks action and attention, cobalt (#3559e8) marks intelligence and links, and sage (#dfeee5) signals healthy governance.

### Layout paradigm
A fixed dark rail anchors navigation on the left; the content area uses an editorial split with an asymmetric primary workspace and a narrow context rail. The roles view uses a table-like list with a focused inspector rather than a generic dashboard grid.

### Signature elements
- Vermilion square mark with a small offset cobalt rule.
- Scope chips that expose the permission boundary in plain language.
- “Signal” insight cards with a short metric, source label, and action link.

### Interaction philosophy
Interactions should feel deliberate and reversible. Role creation happens in a side drawer with explicit scopes and a clear create action. Chat prompt chips preload useful asks rather than guessing. Navigation changes the work surface without losing the current conversation.

### Animation
Use short 160–220ms ease-out transitions for panels, chips, and hover states. Avoid looping motion except the compact thinking indicator. Role drawers slide from the right; cards lift by 2px on hover.

### Typography system
Use Geist Sans for all UI, with tight large headlines, 12px uppercase labels, and readable 14–16px body copy. Use the existing Geist Mono only for IDs, scope keys, and metrics where useful.

### Brand essence
Weber AI is the governed intelligence layer for modern corporate teams: clear, accountable, and ready for action. Personality: precise, calm, capable.

### Brand voice
Headlines sound direct: “Make the next decision obvious.” CTAs sound operational: “Create role”, “Run report”, “Ask about revenue”. Avoid vague AI hype.

### Wordmark & logo
A compact vermilion square containing a white W cut by a cobalt offset bar, paired with the WEBER AI wordmark in a restrained geometric sans.

### Signature brand color
Vermilion #ee6c4d.
