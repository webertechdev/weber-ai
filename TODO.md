# Weber AI delivery outcomes

## Corporate workspace shell
- [x] Preserve the existing streaming chat experience while adding a responsive corporate workspace shell with an ADMIN identity, navigation, active role, and governance status.
- [x] Make the primary ADMIN role visible and make the workspace ready for additional corporate roles without tying it to one industry.

## ADMIN role creation and access
- [x] Allow ADMIN to create additional roles with a name, department, description, status, and explicit access scopes.
- [x] Show the role list with active/inactive state, member count, last activity, and permission boundary so information access is understandable.
- [x] Keep a clear path for non-admin roles to see only their allowed business areas and reports.

## Role-aware AI analysis
- [x] Include the active role and its allowed scopes in the AI request context so the assistant is instructed to limit answers to permitted information.
- [x] Provide reusable corporate analysis prompts for revenue, operations, workforce, risk, and executive briefing use cases.
- [x] Add report-oriented insight cards that make outputs feel like business analysis rather than generic chat.

## Secure website connectors
- [x] Let a signed-in user connect the website used during signup or add another website URL.
- [x] Require explicit authorization state before connector analysis; external passwords must never be sent to or stored by Weber AI.
- [x] Limit analysis requests to the selected connector and record unavailable-information guidance until the authorized session is available.
- [x] Start analysis only when the user clicks Analyze and let the user choose text, PDF, image, Word, Excel/CSV, or PowerPoint output intent.
- [ ] Attach a separate browser-worker/session bridge that can receive the user-authorized session, extract/select large tables, and return temporary evidence.
- [ ] Delete temporary screenshots/evidence after analysis while retaining generated reports for continuation and comparison.
- [ ] Generate the selected PDF, image, Word, Excel/CSV, or PowerPoint artifact from completed analysis evidence.

## Service foundation
- [x] Use Neon PostgreSQL in production with local SQLite fallback for development.
- [x] Add authenticated signup/login, workspace ownership, and ADMIN role creation.
- [x] Add connector and analysis-run persistence plus report-ready API surfaces.
- [ ] Keep the browser-worker/session bridge separate from the Vercel API so provider credentials remain outside Weber AI.

## Validation
- [x] Keep the frontend lintable and buildable with the existing package scripts.
- [x] Keep the backend importable with the existing requirements.
- [ ] Validate connector authorization state and report persistence against the live Neon deployment.
