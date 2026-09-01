// Keep trusted fixtures private regardless of the invoking account's umask.
// Permission-boundary tests still set their unsafe modes explicitly.
if (process.platform !== "win32") {
  process.umask(0o077);
}
