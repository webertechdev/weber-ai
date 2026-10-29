# Weber AI corporate workspace and governed connectors plan

## Implementation

Preserve the existing authenticated Next.js/FastAPI corporate workspace and extend it with a reusable, role-aware connector and report layer. The first connector type is a user-authorized browser session for the company website or an additional URL. Weber AI must never receive or store the external website password. A future browser-worker/session bridge will open the target website, let the user authenticate directly, display requested access, and return only approved page evidence to the analysis job.

The connector layer stores the website URL, authorization state, allowed page scope, audit timestamps, and revocation state. Analysis runs are user-started only. The analysis request is constrained to the active connector session; if requested information is not visible in that session, the assistant must say it is unavailable and recommend the appropriate IT/admin/data owner. Screenshots and temporary captures are disposable evidence. Generated reports persist for future continuation and comparison.

Report export is format-selected by the user. The platform supports text chat by default and prepares PDF, image, Word, Excel/CSV, and PowerPoint export jobs as the corresponding generators are connected. Large browser tables should first use structured page extraction or select-all/copy when no API/export exists; an API/database connector can replace this later.

Project structure:
- `frontend/app/page.tsx`: authenticated workspace, connector authorization surface, analysis request, role-aware chat, and report library.
- `frontend/app/globals.css` and `frontend/app/auth.css`: warm enterprise intelligence console styling.
- `backend/models.py`: users, workspaces, roles, connectors, analysis runs, reports, and temporary evidence metadata.
- `backend/main.py`: authenticated connector CRUD, authorization state, analysis requests, and report persistence endpoints.
- `backend/database.py`: local/Neon database selection.

## Security boundary

External credentials are entered only in the provider/browser authorization surface. Weber AI does not accept, log, store, or proxy external passwords. Connector access is explicit, revocable, scoped, and tied to the signed-in workspace member and active role. The generic browser worker is intentionally a separate service boundary from the Vercel API; it must be attached before real arbitrary-site navigation is enabled in production.

## Design

Use the existing chosen warm enterprise intelligence console: dark command rail, paper-white canvas, vermilion action color, cobalt intelligence accents, visible role/scope chips, calm dense cards, and explicit governance language. Connector cards should make authorization status, website URL, last run, scope, and revoke action immediately visible. Analysis cards should show source connector, user request, status, retained report, and export format.
