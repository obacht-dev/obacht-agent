-- Add an optional app_path to instance_services (spec v2.8 service.appPath).
-- When a service bound at the domain root has app_path set, the Caddy renderer
-- emits `redir / <app_path>` so visitors landing on the bare root are sent to
-- the app's entry page (e.g. MediaMTX serving under /cam/). Nullable/additive.
ALTER TABLE instance_services ADD COLUMN app_path TEXT;
