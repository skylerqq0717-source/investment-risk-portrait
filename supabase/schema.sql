-- Deploy in this project's Supabase SQL Editor. Only anonymous score summaries are stored.
create table if not exists public.shared_results (
  id uuid primary key default gen_random_uuid(),
  capacity_score smallint not null check (capacity_score between 0 and 20),
  tolerance_score smallint not null check (tolerance_score between 0 and 20),
  knowledge_score smallint not null check (knowledge_score between 0 and 4),
  archetype_index smallint not null check (archetype_index between 0 and 4),
  created_at timestamptz not null default now()
);

alter table public.shared_results enable row level security;
revoke all on table public.shared_results from anon, authenticated;

create schema if not exists quiz_private;
revoke all on schema quiz_private from public, anon, authenticated;

create table if not exists quiz_private.quiz_gate (
  id boolean primary key default true check (id),
  access_code text not null check (access_code ~ '^[0-9]{6}$')
);
create table if not exists quiz_private.quiz_sessions (
  token_hash text primary key,
  expires_at timestamptz not null
);
create table if not exists quiz_private.quiz_attempts (
  ip_hash text primary key,
  attempts integer not null,
  reset_at timestamptz not null
);
revoke all on all tables in schema quiz_private from public, anon, authenticated;

create or replace function public.quiz_verify(p_code text)
returns jsonb
language plpgsql security definer set search_path = ''
as $$
declare
  v_code text;
  v_headers jsonb;
  v_ip text;
  v_ip_hash text;
  v_attempts integer;
  v_token text;
begin
  select access_code into v_code from quiz_private.quiz_gate where id = true;
  if v_code is null then
    return jsonb_build_object('ok', false, 'error', '测评服务尚未配置');
  end if;

  v_headers := nullif(current_setting('request.headers', true), '')::jsonb;
  v_ip := nullif(trim(split_part(coalesce(v_headers->>'x-forwarded-for', ''), ',', 1)), '');
  if v_ip is not null then
    v_ip_hash := md5(v_ip);
    select attempts into v_attempts
      from quiz_private.quiz_attempts
      where ip_hash = v_ip_hash and reset_at > now();
    if coalesce(v_attempts, 0) >= 8 then
      return jsonb_build_object('ok', false, 'error', '尝试次数较多，请 15 分钟后再试');
    end if;
  end if;

  if p_code is distinct from v_code then
    if v_ip_hash is not null then
      insert into quiz_private.quiz_attempts (ip_hash, attempts, reset_at)
      values (v_ip_hash, 1, now() + interval '15 minutes')
      on conflict (ip_hash) do update set
        attempts = case when quiz_private.quiz_attempts.reset_at <= now()
          then 1 else quiz_private.quiz_attempts.attempts + 1 end,
        reset_at = case when quiz_private.quiz_attempts.reset_at <= now()
          then now() + interval '15 minutes' else quiz_private.quiz_attempts.reset_at end;
    end if;
    return jsonb_build_object('ok', false, 'error', '口令错误');
  end if;

  if v_ip_hash is not null then
    delete from quiz_private.quiz_attempts where ip_hash = v_ip_hash;
  end if;
  v_token := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
  insert into quiz_private.quiz_sessions (token_hash, expires_at)
  values (md5(v_token), now() + interval '7 days');
  return jsonb_build_object('ok', true, 'token', v_token);
end;
$$;

create or replace function public.quiz_create(
  p_token text, p_capacity_score smallint, p_tolerance_score smallint, p_knowledge_score smallint
)
returns jsonb
language plpgsql security definer set search_path = ''
as $$
declare v_id uuid;
begin
  if p_token is null or p_token !~ '^[0-9a-f]{64}$' or not exists (
    select 1 from quiz_private.quiz_sessions
    where token_hash = md5(p_token) and expires_at > now()
  ) then
    return jsonb_build_object('ok', false, 'error', '访问凭证已失效，请重新输入测评密码');
  end if;
  if p_capacity_score not between 0 and 20 or p_tolerance_score not between 0 and 20
    or p_knowledge_score not between 0 and 4 then
    return jsonb_build_object('ok', false, 'error', '测评分数无效');
  end if;
  insert into public.shared_results (
    capacity_score, tolerance_score, knowledge_score, archetype_index
  ) values (
    p_capacity_score, p_tolerance_score, p_knowledge_score,
    least(4, floor(least(p_capacity_score, p_tolerance_score) / 4.01)::smallint)
  ) returning id into v_id;
  return jsonb_build_object('ok', true, 'id', v_id);
end;
$$;

create or replace function public.quiz_read(p_token text, p_id uuid)
returns jsonb
language plpgsql security definer set search_path = ''
as $$
declare v_result jsonb;
begin
  if p_token is null or p_token !~ '^[0-9a-f]{64}$' or not exists (
    select 1 from quiz_private.quiz_sessions
    where token_hash = md5(p_token) and expires_at > now()
  ) then
    return jsonb_build_object('ok', false, 'error', '访问凭证已失效，请重新输入测评密码');
  end if;
  select to_jsonb(r) into v_result from (
    select id, capacity_score, tolerance_score, knowledge_score, archetype_index, created_at
    from public.shared_results where id = p_id
  ) r;
  if v_result is null then
    return jsonb_build_object('ok', false, 'error', '没有找到这份测评结果');
  end if;
  return jsonb_build_object('ok', true, 'result', v_result);
end;
$$;

revoke all on function public.quiz_verify(text) from public, anon, authenticated;
revoke all on function public.quiz_create(text, smallint, smallint, smallint) from public, anon, authenticated;
revoke all on function public.quiz_read(text, uuid) from public, anon, authenticated;
grant execute on function public.quiz_verify(text) to anon, authenticated;
grant execute on function public.quiz_create(text, smallint, smallint, smallint) to anon, authenticated;
grant execute on function public.quiz_read(text, uuid) to anon, authenticated;

-- The access code is set separately by the project owner in SQL Editor.
-- insert into quiz_private.quiz_gate (id, access_code) values (true, '<six-digit code>')
-- on conflict (id) do update set access_code = excluded.access_code;
