-- In Supabase SQL Editor, replace the placeholder yourself and run this query.
-- Never commit a copy containing the real access code.
insert into quiz_private.quiz_gate (id, access_code)
values (true, '在这里输入六位入口密码')
on conflict (id) do update set access_code = excluded.access_code;
