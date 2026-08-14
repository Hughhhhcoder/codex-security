import { describe, expect, test } from "bun:test";

type PackageTarListing = {
  regularTarListingLines: (listing: string) => string[];
};

const { regularTarListingLines } = (await import(
  new URL("../scripts/package-tar-listing.mjs", import.meta.url).href
)) as PackageTarListing;

describe("npm package tar listings", () => {
  test("accepts regular entries with Unix or Windows line endings", () => {
    const file = "-rw-r--r-- package/package.json";
    const directory = "drwxr-xr-x package/dist/";

    expect(regularTarListingLines(`${file}\n${directory}\n`)).toEqual([
      file,
      directory,
    ]);
    expect(regularTarListingLines(`${file}\r\n${directory}\r\n`)).toEqual([
      file,
      directory,
    ]);
  });

  test("rejects symbolic links and other non-regular entries", () => {
    expect(() =>
      regularTarListingLines("lrwxrwxrwx package/link -> target\r\n"),
    ).toThrow("npm tarball contains a non-regular entry");
  });
});
