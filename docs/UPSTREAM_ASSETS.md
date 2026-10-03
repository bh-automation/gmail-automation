# Upstream design and API assets

## Microsoft Fluent 2
Recommended production UI foundation: Fluent UI React v9 via `@fluentui/react-components`. The official Fluent 2 guidance maps design assets/tokens to code libraries; the official Figma UI kit remains upstream and is not redistributed in this bundle.

## Gmail
Use the official Gmail API client libraries and OAuth 2.0 documentation. Choose the narrowest scopes possible. This package explicitly forbids the full-mail scope that permits permanent deletion.

## Why upstream assets are not copied here
This pack avoids bundling third-party UI kits, logos, fonts or node_modules. It contains source references and starter code only, keeping the repository smaller and avoiding stale/vendor-controlled assets.
