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

## Service foundation
- [x] Add SQLite-backed corporate role and role-scope models while keeping existing conversations and messages working.
- [x] Add role list/create/update endpoints and accept an active role on streaming chat requests.
- [x] Expose the single-page frontend route through the required route manifest.

## Validation
- [x] Keep the frontend lintable and buildable with the existing package scripts.
- [x] Keep the backend importable with the existing requirements and avoid requiring a new external service for the role foundation.
