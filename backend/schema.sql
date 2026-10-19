create table if not exists public.zhi_accounts (
 name text primary key, salt text not null, password_hash text not null,
 iterations integer not null default 210000, role text not null check(role in ('member','admin')),
 active boolean not null default true
);
create table if not exists public.zhi_sessions (
 token_hash text primary key, name text not null references public.zhi_accounts(name), expires_at timestamptz not null
);
create index if not exists zhi_sessions_expiry on public.zhi_sessions(expires_at);
create table if not exists public.zhi_state (
 id integer primary key check(id=1), version integer not null default 0,
 data jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now()
);
create table if not exists public.zhi_login_limits (
 bucket text primary key, attempts integer not null default 1, expires_at timestamptz not null
);
alter table public.zhi_accounts enable row level security;
alter table public.zhi_sessions enable row level security;
alter table public.zhi_state enable row level security;
alter table public.zhi_login_limits enable row level security;
revoke all on public.zhi_accounts,public.zhi_sessions,public.zhi_state,public.zhi_login_limits from anon,authenticated;
grant all on public.zhi_accounts,public.zhi_sessions,public.zhi_state,public.zhi_login_limits to service_role;
create or replace function public.zhi_rate_limit(p_bucket text) returns integer
language plpgsql security invoker set search_path='' as $$
declare n integer;
begin
 delete from public.zhi_login_limits where expires_at < now();
 insert into public.zhi_login_limits(bucket,attempts,expires_at) values(p_bucket,1,now()+interval '5 minutes')
 on conflict(bucket) do update set attempts=public.zhi_login_limits.attempts+1
 returning attempts into n;
 return n;
end; $$;
revoke all on function public.zhi_rate_limit(text) from public,anon,authenticated;
grant execute on function public.zhi_rate_limit(text) to service_role;
insert into public.zhi_state(id,data) values(1,'{"tasks":[],"updates":[],"reports":[],"shares":[],"minutes":[],"insights":[],"leaves":[],"assignmentRules":[],"weeklyPlans":{},"communityChecks":{},"ruleNotes":"","roster":[]}'::jsonb) on conflict(id) do nothing;

-- AI provider key: server-only access, never returned to the frontend.
create table if not exists public.zhi_ai_config (id integer primary key check(id=1), provider text not null check(provider in ('doubao','deepseek','openai')), model text not null, api_key text not null, updated_at timestamptz not null default now());
alter table public.zhi_ai_config enable row level security;
revoke all on public.zhi_ai_config from anon,authenticated;
grant all on public.zhi_ai_config to service_role;
