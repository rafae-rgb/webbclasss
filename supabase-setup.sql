-- Buat akun teman sekelas di Supabase Authentication dan nonaktifkan pendaftaran publik.
-- Jalankan skrip ini dari Supabase Dashboard > SQL Editor.
-- Setelah akun dibuat, daftarkan UUID setiap anggota:
-- insert into public.class_members (user_id) values ('UUID-AKUN-DARI-AUTH-USERS');

create table if not exists public.class_events (
  id text primary key,
  name text not null check (char_length(name) between 1 and 120),
  event_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists public.class_photos (
  id text primary key,
  image_url text not null,
  alt_text text not null,
  caption text not null check (char_length(caption) between 1 and 120),
  storage_path text,
  created_at timestamptz not null default now()
);

alter table public.class_events enable row level security;
alter table public.class_photos enable row level security;

create table if not exists public.class_members (
  user_id uuid primary key references auth.users(id) on delete cascade
);
alter table public.class_members enable row level security;

create or replace function public.is_class_member()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.class_members
    where user_id = auth.uid()
  );
$$;

revoke all on function public.is_class_member() from public;
grant execute on function public.is_class_member() to authenticated;

revoke all on public.class_members from anon, authenticated;
revoke insert, delete on public.class_events from anon, authenticated;
revoke insert, delete on public.class_photos from anon, authenticated;
grant select on public.class_events to anon, authenticated;
grant select on public.class_photos to anon, authenticated;
grant insert on public.class_events to authenticated;
grant delete on public.class_events to authenticated;
grant insert on public.class_photos to authenticated;
grant delete on public.class_photos to authenticated;

drop policy if exists "Public can read class events" on public.class_events;
create policy "Public can read class events"
  on public.class_events for select to anon, authenticated
  using (true);

drop policy if exists "Public can add class events" on public.class_events;
drop policy if exists "Class members can add class events" on public.class_events;
create policy "Class members can add class events"
  on public.class_events for insert to authenticated
  with check (public.is_class_member());

drop policy if exists "Public can delete class events" on public.class_events;
drop policy if exists "Class members can delete class events" on public.class_events;
create policy "Class members can delete class events"
  on public.class_events for delete to authenticated
  using (public.is_class_member());

drop policy if exists "Public can read class photos" on public.class_photos;
create policy "Public can read class photos"
  on public.class_photos for select to anon, authenticated
  using (true);

drop policy if exists "Public can add class photos" on public.class_photos;
drop policy if exists "Class members can add class photos" on public.class_photos;
create policy "Class members can add class photos"
  on public.class_photos for insert to authenticated
  with check (public.is_class_member());

drop policy if exists "Public can delete class photos" on public.class_photos;
drop policy if exists "Class members can delete class photos" on public.class_photos;
create policy "Class members can delete class photos"
  on public.class_photos for delete to authenticated
  using (public.is_class_member());

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'class-photos',
  'class-photos',
  true,
  1048576,
  array['image/jpeg', 'image/png', 'image/gif', 'image/webp']
)
on conflict (id) do update
set public = excluded.public,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Public can view class photo files" on storage.objects;
create policy "Public can view class photo files"
  on storage.objects for select to anon, authenticated
  using (bucket_id = 'class-photos');

drop policy if exists "Public can upload class photo files" on storage.objects;
drop policy if exists "Class members can upload class photo files" on storage.objects;
create policy "Class members can upload class photo files"
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'class-photos'
    and public.is_class_member()
  );

drop policy if exists "Public can delete class photo files" on storage.objects;
drop policy if exists "Class members can delete class photo files" on storage.objects;
create policy "Class members can delete class photo files"
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'class-photos'
    and public.is_class_member()
  );
