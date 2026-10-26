-- ПОЛОМКА CI (временно, Р-199; PS-05в ч. 2б-1 К1а): без agents_suspended_at. Убирается git revert.
ALTER TABLE agents DROP CONSTRAINT agents_suspended_at;
