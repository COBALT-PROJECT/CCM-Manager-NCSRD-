# CCM_Manager_API Structure

This document summarizes the main modules and how they connect.

## High-level flow

- app.py defines the Flask API and delegates to service modules.
- services/* implement domain operations and call shared modules.
- db.py configures MongoDB collections used by services.
- auth.py centralizes outbound request auth.
- config.py defines environment-driven settings.
- utils.py provides small helpers used across services and app.

## Key connections

- app.py -> services/*.py
- services/* -> db.py (Mongo collections)
- services/* -> auth.py (authed_request)
- services/* -> config.py (URLs, paths)
- assessment_service.py + certification_scheme_service.py -> services/ledger.py
- cbom_workflow.py -> generate_tree.py + algos_details.py
- sbom_workflow.py -> helpers/*.sh (generate_sbom.sh, create_project.sh)

## Folders

- services/ : domain services used by API endpoints
- scripts/  : one-off scripts to seed data or test endpoints
- tests/    : integration/unit test scripts
- data/     : JSON payloads used by scripts and app startup
- sboms/    : generated SBOM outputs (runtime)
- tmp/      : temporary files (runtime)
- helpers/  : shell helpers invoked by SBOM workflow
- schemas/  : JSON schemas for validation
- mongo-data/ : local MongoDB data

## Related documentation

- database_schema.md documents the MongoDB collections, document shapes, and application-level relations.
