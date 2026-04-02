-- BLD Initial Schema
-- Profiles, projects, tasks, credit transactions, daily stats

-- ── Profiles (extends auth.users) ─────────────────────────────
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  tier text not null default 'free' check (tier in ('free', 'pro', 'pro_byok', 'team')),
  credits numeric not null default 0,
  stripe_customer_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "Users can read own profile"
  on public.profiles for select using (auth.uid() = id);
create policy "Users can update own profile"
  on public.profiles for update using (auth.uid() = id);

-- Auto-create profile on signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email)
  values (new.id, new.email);
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── Projects ──────────────────────────────────────────────────
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  name text not null,
  directory text not null,
  dev_server_url text,
  confidence_threshold int not null default 80,
  default_model text not null default 'anthropic/claude-sonnet-4.6',
  created_at timestamptz not null default now()
);

alter table public.projects enable row level security;

create policy "Users can CRUD own projects"
  on public.projects for all using (auth.uid() = user_id);

create index idx_projects_user on public.projects(user_id);

-- ── Tasks ─────────────────────────────────────────────────────
create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid references public.projects(id) on delete set null,
  user_id uuid not null references public.profiles(id) on delete cascade,
  prompt text not null,
  status text not null default 'queued'
    check (status in ('queued','chunking','running','validating','retrying','needs_review','approved','rejected')),
  model text,
  classification jsonb,
  confidence int,
  reasoning text,
  cost numeric not null default 0,
  input_tokens int not null default 0,
  output_tokens int not null default 0,
  files_changed jsonb,
  diff text,
  before_screenshot text,
  after_screenshot text,
  auto_approved boolean not null default false,
  human_verdict text,
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

alter table public.tasks enable row level security;

create policy "Users can CRUD own tasks"
  on public.tasks for all using (auth.uid() = user_id);

create index idx_tasks_user on public.tasks(user_id);
create index idx_tasks_project on public.tasks(project_id);
create index idx_tasks_status on public.tasks(status);

-- ── Credit Transactions ───────────────────────────────────────
create table public.credit_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  amount numeric not null,
  type text not null check (type in ('purchase', 'task', 'refund', 'monthly_free')),
  description text,
  task_id uuid references public.tasks(id) on delete set null,
  stripe_payment_id text,
  balance_after numeric not null default 0,
  created_at timestamptz not null default now()
);

alter table public.credit_transactions enable row level security;

create policy "Users can read own transactions"
  on public.credit_transactions for select using (auth.uid() = user_id);

create index idx_transactions_user on public.credit_transactions(user_id);

-- ── Daily Stats ───────────────────────────────────────────────
create table public.daily_stats (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  date date not null,
  tasks_completed int not null default 0,
  tasks_approved int not null default 0,
  tasks_rejected int not null default 0,
  credits_spent numeric not null default 0,
  tokens_used int not null default 0,
  streak_days int not null default 0,
  unique(user_id, date)
);

alter table public.daily_stats enable row level security;

create policy "Users can read own stats"
  on public.daily_stats for select using (auth.uid() = user_id);

create index idx_stats_user_date on public.daily_stats(user_id, date);

-- ── Helper: deduct credits atomically ─────────────────────────
create or replace function public.deduct_credits(
  p_user_id uuid,
  p_amount numeric,
  p_task_id uuid default null,
  p_description text default null
)
returns jsonb as $$
declare
  v_balance numeric;
  v_new_balance numeric;
begin
  -- Lock the row
  select credits into v_balance
  from public.profiles
  where id = p_user_id
  for update;

  if v_balance is null then
    return jsonb_build_object('success', false, 'error', 'user_not_found');
  end if;

  if v_balance < p_amount then
    return jsonb_build_object('success', false, 'error', 'insufficient_credits', 'balance', v_balance);
  end if;

  v_new_balance := v_balance - p_amount;

  update public.profiles set credits = v_new_balance, updated_at = now()
  where id = p_user_id;

  insert into public.credit_transactions (user_id, amount, type, description, task_id, balance_after)
  values (p_user_id, -p_amount, 'task', p_description, p_task_id, v_new_balance);

  return jsonb_build_object('success', true, 'balance', v_new_balance, 'charged', p_amount);
end;
$$ language plpgsql security definer;

-- ── Helper: add credits (purchase/monthly free) ───────────────
create or replace function public.add_credits(
  p_user_id uuid,
  p_amount numeric,
  p_type text default 'purchase',
  p_stripe_payment_id text default null,
  p_description text default null
)
returns jsonb as $$
declare
  v_new_balance numeric;
begin
  update public.profiles
  set credits = credits + p_amount, updated_at = now()
  where id = p_user_id
  returning credits into v_new_balance;

  if v_new_balance is null then
    return jsonb_build_object('success', false, 'error', 'user_not_found');
  end if;

  insert into public.credit_transactions (user_id, amount, type, description, stripe_payment_id, balance_after)
  values (p_user_id, p_amount, p_type, p_description, p_stripe_payment_id, v_new_balance);

  return jsonb_build_object('success', true, 'balance', v_new_balance);
end;
$$ language plpgsql security definer;

-- ── Helper: update daily stats ────────────────────────────────
create or replace function public.increment_daily_stat(
  p_user_id uuid,
  p_field text,
  p_value numeric default 1
)
returns void as $$
begin
  insert into public.daily_stats (user_id, date, tasks_completed, tasks_approved, tasks_rejected, credits_spent, tokens_used)
  values (p_user_id, current_date, 0, 0, 0, 0, 0)
  on conflict (user_id, date) do nothing;

  execute format(
    'update public.daily_stats set %I = %I + $1 where user_id = $2 and date = current_date',
    p_field, p_field
  ) using p_value, p_user_id;
end;
$$ language plpgsql security definer;
