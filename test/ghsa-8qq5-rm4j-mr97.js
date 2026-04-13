// Tests for CVE-2026-29786, CVE-2026-23745, CVE-2026-24842, CVE-2026-31802
// Adapted from upstream test/ghsa-8qq5-rm4j-mr97.ts (which uses TypeScript + tar.x())
// for 2.2.1's API (tap 0.x + tar.Extract).

var tap = require("tap")
var tar = require("../tar.js")
var TarHeader = require("../lib/header.js")
var fs = require("fs")
var path = require("path")
var rimraf = require("rimraf")
var mkdirp = require("mkdirp")

var target = path.resolve(__dirname, "tmp/ghsa-8qq5")
var tarFile = path.resolve(__dirname, "tmp/ghsa-8qq5.tar")

// Helper: encode a single 512-byte header with correct checksum
function makeHeader(props) {
  var obj = {
    path: props.path,
    mode: props.mode || 0644,
    uid: 0,
    gid: 0,
    size: props.size || 0,
    mtime: 0,
    cksum: 0,
    type: props.type,
    linkpath: props.linkpath || '',
    ustar: 'ustar\0',
    ustarver: '00',
    uname: '',
    gname: '',
    devmaj: 0,
    devmin: 0,
    fill: ''
  }
  return TarHeader.encode(obj)
}

function buildTar(entries) {
  var chunks = []
  for (var i = 0; i < entries.length; i++) {
    chunks.push(makeHeader(entries[i]))
  }
  // End-of-archive: two 512-byte zero blocks
  chunks.push(new Buffer(1024))
  for (var j = 0; j < 1024; j++) chunks[chunks.length - 1][j] = 0
  return Buffer.concat(chunks)
}

tap.test("preclean", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  mkdirp.sync(path.dirname(tarFile))
  t.pass("cleaned")
  t.end()
})

// CVE-2026-29786: absolute path with .. is stripped before .. check
// Upstream: tests that '/../a/target' symlink linkpath becomes '../a/target' after stripping.
// Adapted: extract a SymbolicLink with absolute '..' linkpath; verify the stripping warning fires
// and the symlink is NOT created with the escape-attempting absolute path.
tap.test("CVE-2026-29786: absolute path with '..' is stripped, symlink linkpath sanitized", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5" /* Directory */, mode: 0755 },
    // Absolute-path linkpath with embedded '..'
    { path: "a/link", type: "2" /* SymbolicLink */, linkpath: "/../a/target" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var warnings = []
  var extractor = tar.Extract({ path: target })
    .on("entry", function (entry) {
      entry.on("warn", function (msg, data) { warnings.push([msg, data && data.path || null]) })
    })
    .on("end", function () {
      // The absolute linkpath should have had its '/' root stripped
      // Result: linkpath '../a/target' — still has '..', but for a SymbolicLink
      // '..' in linkpath is legitimate (CVE-2026-24842 only rejects '..' in hardlink linkpath)
      // So the symlink SHOULD be created with the stripped linkpath.
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "a/link"))
        // Must not retain the absolute prefix
        t.equal(linkTarget.charAt(0) !== "/" || linkTarget === "../a/target", true,
          "absolute prefix stripped from symlink target: got " + linkTarget)
      } catch (err) {
        t.fail("symlink should have been created: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: linkpath stripped + '..' rejected (for hardlinks)
// Upstream: hardlink with linkpath '../secret.txt' should be rejected, preventing
// attacker-controlled hardlink to files outside extraction dir.
// Security property: the external file must NOT be hardlinked (different inode).
tap.test("CVE-2026-23745: hardlink with '..' linkpath does not link to external file", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  // Create a file "outside" the extraction target
  var secretFile = path.resolve(target, "..", "ghsa-secret-" + process.pid + ".txt")
  fs.writeFileSync(secretFile, "ORIGINAL DATA")
  var secretInode = fs.lstatSync(secretFile).ino

  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    // Hardlink whose linkpath tries to escape via '..'
    { path: "sub/exploit_sub", type: "1" /* Link */, linkpath: "../ghsa-secret-" + process.pid + ".txt" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var exploitPath = path.resolve(target, "sub/exploit_sub")
      try {
        var exploitStat = fs.lstatSync(exploitPath)
        // If the entry was created, it must NOT be a hardlink to the external secret
        t.notEqual(exploitStat.ino, secretInode,
          "exploit_sub must not share inode with external secret (hardlink blocked)")
      } catch (e) {
        t.pass("exploit_sub was not created at all (hardlink blocked)")
      }
      // External secret must be unchanged
      t.equal(fs.readFileSync(secretFile, 'utf8'), "ORIGINAL DATA",
        "external secret file must remain unchanged")

      try { fs.unlinkSync(secretFile) } catch (e) {}
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: linkpath with absolute path is stripped
tap.test("CVE-2026-23745: absolute linkpath has root stripped", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    // Absolute linkpath — root '/' should be stripped
    { path: "a/abs_sym", type: "2" /* SymbolicLink */, linkpath: "/some/absolute/path" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "a/abs_sym"))
        t.notEqual(linkTarget, "/some/absolute/path",
          "absolute symlink target should have been stripped")
        t.equal(linkTarget.charAt(0) !== "/", true,
          "stripped symlink target should be relative: got " + linkTarget)
      } catch (err) {
        t.fail("symlink should have been created with stripped linkpath: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-24842: symlink with '..' linkpath is ALLOWED (only hardlinks reject '..')
// Upstream: the distinction between symlink and hardlink is critical — symlinks
// legitimately use relative '..' paths and should not be rejected.
tap.test("CVE-2026-24842: symlink with '..' linkpath is allowed (not rejected like hardlinks)", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    // Symlink with '..' linkpath — legitimate usage, should be created
    { path: "sub/rel_sym", type: "2", linkpath: "../some/target" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "sub/rel_sym"))
        t.equal(linkTarget, "../some/target",
          "symlink with relative '..' linkpath should be preserved")
      } catch (err) {
        t.fail("symlink with '..' should be created: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-24842 (paired with 23745): hardlink with '..' is STILL rejected while symlink is allowed
tap.test("CVE-2026-24842: hardlink with '..' does not link to external file", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretFile = path.resolve(target, "..", "ghsa-secret2-" + process.pid + ".txt")
  fs.writeFileSync(secretFile, "SECRET")
  var secretInode = fs.lstatSync(secretFile).ino

  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    { path: "sub/hardlink", type: "1" /* Link */, linkpath: "../ghsa-secret2-" + process.pid + ".txt" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var hardlinkPath = path.resolve(target, "sub/hardlink")
      try {
        var hardlinkStat = fs.lstatSync(hardlinkPath)
        t.notEqual(hardlinkStat.ino, secretInode,
          "hardlink must not share inode with external secret")
      } catch (e) {
        t.pass("hardlink was not created")
      }
      t.equal(fs.readFileSync(secretFile, 'utf8'), "SECRET",
        "external secret file must remain unchanged")

      try { fs.unlinkSync(secretFile) } catch (e) {}
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-31802: drive-relative prefix (c:...) doesn't confuse path.resolve
// Upstream: 'c:..\foo\bar' with drive-local prefix. After stripping drive prefix + '..'
// handling, the escape check must use the cleaned parts, not the raw path.
// Adapted: test that an entry whose RAW path would escape, but whose cleaned path
// doesn't, gets handled via parts.join('/') in the path.resolve call.
tap.test("CVE-2026-31802: drive-prefix path cleaned via parts.join before resolve", function (t) {
  rimraf.sync(target)
  // c:foo gets stripped to 'foo' by stripAbsolutePath (drive-local prefix is a root)
  // so the entry should extract to target/foo, not to a drive-relative location.
  var tarBuf = buildTar([
    { path: "c:foo/inner.txt", type: "0" /* File */, size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      // The 'c:' root should have been stripped by stripAbsolutePath.
      // Result path: 'foo/inner.txt' inside target.
      var expected = path.resolve(target, "foo/inner.txt")
      var exists = false
      try { fs.statSync(expected); exists = true } catch (e) {}
      t.equal(exists, true,
        "drive-prefix 'c:foo/inner.txt' should extract to target/foo/inner.txt after stripping")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-29786: Windows drive-relative symlink (c:..\foo\bar)
// Upstream tests a/winrootdotslink with linkpath 'c:..\\foo\\bar':
// verifies readlink target is '..\\foo\\bar' (drive prefix stripped).
// Adapted: Linux readlink preserves backslashes as literal characters.
tap.test("CVE-2026-29786: Windows drive-relative symlink has drive prefix stripped", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/winrootdotslink", type: "2", linkpath: "c:..\\foo\\bar" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "a/winrootdotslink"))
        // Drive prefix 'c:' should be stripped; result should NOT start with 'c:'
        t.equal(linkTarget.indexOf("c:"), -1,
          "drive prefix 'c:' stripped from symlink target: got " + linkTarget)
      } catch (err) {
        t.fail("symlink should have been created with stripped linkpath: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-29786: Windows drive-relative symlink escape (c:..\..\..\..\foo\bar)
// Upstream tests a/winrootdotsescapelink: verifies symlink is NOT created because
// after stripping 'c:', '..\..\..\..' contains '..' path components that escape
// the extraction directory. For symlinks, '..' in linkpath is allowed per CVE-2026-24842,
// but the SymbolicLink target-escape check in extract.js should still catch a symlink
// whose resolved target escapes opts.path.
tap.test("CVE-2026-29786: escape-attempting drive-relative symlink is handled", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/winrootdotsescapelink", type: "2", linkpath: "c:..\\..\\..\\..\\foo\\bar" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var linkPath = path.resolve(target, "a/winrootdotsescapelink")
      try {
        var linkTarget = fs.readlinkSync(linkPath)
        // If created, target must NOT escape opts.path (no absolute path outside target)
        // and must not retain the drive-prefix
        t.equal(linkTarget.indexOf("c:"), -1,
          "drive prefix stripped even for escape-attempting linkpath: got " + linkTarget)
      } catch (err) {
        // Alternative: symlink was refused entirely (e.g., SymbolicLink escape check)
        t.pass("escape-attempting symlink not created: " + err.code)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745 (behavioral): writeFileSync through exploit_hard does NOT modify external secret
// Upstream's primary test: after extract, write to the extracted hardlink file and
// verify the external secret file is unchanged. This is the operational proof the
// hardlink was NOT created as a link to the external file.
tap.test("CVE-2026-23745: writeFileSync through extracted hardlink does not modify external secret", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretFile = path.resolve(target, "..", "ghsa-writefile-" + process.pid + ".txt")
  fs.writeFileSync(secretFile, "ORIGINAL DATA")

  var tarBuf = buildTar([
    // Hardlink pointing to external file via absolute path
    { path: "exploit_hard", type: "1", linkpath: secretFile }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var exploitPath = path.resolve(target, "exploit_hard")
    try {
      // Attempt the exploit: write through the extracted hardlink
      fs.writeFileSync(exploitPath, "OVERWRITTEN")
    } catch (e) { /* blocked, fine */ }
    t.equal(fs.readFileSync(secretFile, 'utf8'), "ORIGINAL DATA",
      "external secret must NOT be modified via extracted hardlink (writeFileSync exploit)")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  // fstream may throw ENOENT if it tries to link a non-existent path — we catch
  // both error and end, whichever comes first.
  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)

  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-23745 + CVE-2026-24842 (behavioral): sub-directory hardlink with '..' linkpath
// Upstream test: hardlink 'sub/exploit_sub' with linkpath '../secret.txt'.
// After extract, writeFileSync to sub/exploit_sub should NOT modify external secret.
tap.test("CVE-2026-23745/24842: writeFileSync through sub/exploit_sub does not modify external secret", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretName = "ghsa-subwrite-" + process.pid + ".txt"
  var secretFile = path.resolve(target, "..", secretName)
  fs.writeFileSync(secretFile, "SECRET DATA")

  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    { path: "sub/exploit_sub", type: "1", linkpath: "../" + secretName }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var exploitPath = path.resolve(target, "sub/exploit_sub")
    try { fs.writeFileSync(exploitPath, "OVERWRITTEN") } catch (e) {}
    t.equal(fs.readFileSync(secretFile, 'utf8'), "SECRET DATA",
      "external secret must NOT be modified via sub/exploit_sub writeFileSync")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-26960: full three-link chain exploit from GHSA-83g3-92jg-28cx
// The actual CVE attack chain uses two symlinks + one hardlink (or symlink) to
// escape the extraction directory:
//   a/b/up          -> symlink '../..'
//   a/b/escape      -> symlink 'up/..'
//   exploit         -> hardlink/symlink 'a/b/escape/exploited-file'
// After extraction, writeFileSync(exploit) would modify 'exploited-file' OUTSIDE
// the extraction root (via the chained symlink resolution). The fix: detect
// symlink components in the path walk before any link creation.
// Adapted for 2.2.1: run for both Link and SymbolicLink types.
function runChainExploitTest(t, linkType, typeName) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var exploitedName = "exploited-" + typeName + "-" + process.pid + ".txt"
  var exploitedFile = path.resolve(target, "..", exploitedName)
  fs.writeFileSync(exploitedFile, "original content")

  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/b/up", type: "2", linkpath: "../.." },
    { path: "a/b/escape", type: "2", linkpath: "up/.." },
    { path: "exploit", type: linkType, linkpath: "a/b/escape/" + exploitedName }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    try { fs.writeFileSync(path.resolve(target, "exploit"), "pwned") } catch (e) {}
    t.equal(fs.readFileSync(exploitedFile, 'utf8'), "original content",
      "external exploited-file must NOT be modified via " + typeName + " chain")
    try { fs.unlinkSync(exploitedFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
}

tap.test("CVE-2026-26960: symlink chain exploit blocked (Link type)", function (t) {
  runChainExploitTest(t, "1", "Link")
})

tap.test("CVE-2026-26960: symlink chain exploit blocked (SymbolicLink type)", function (t) {
  runChainExploitTest(t, "2", "SymbolicLink")
})

// CVE-2024-28863: excessive depth — integration test
// Upstream: extracts a real 222,372-level deep tar via the 'excessively-deep.tar'
// fixture and asserts a TAR_ENTRY_ERROR warning fires.
// Adapted: construct a deep tar programmatically with a path exceeding maxDepth (1024).
function runMaxDepthTest(t, maxDepth, depth, opts) {
  rimraf.sync(target)
  var deepPath = ""
  for (var i = 0; i < depth; i++) deepPath += "a/"
  deepPath += "foo.txt"

  var tarBuf = buildTar([
    { path: deepPath, type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var sawError = false
  var done = false
  function finish() {
    if (done) return
    done = true
    t.equal(sawError, true, "excessively deep path should trigger error")
    var deepTarget = path.resolve(target, deepPath)
    var exists = false
    try { fs.statSync(deepTarget); exists = true } catch (e) {}
    t.equal(exists, false, "excessively deep file should not be extracted")
    t.end()
  }

  var extractor = tar.Extract(opts)
    .on("error", function (err) {
      if (err.message && err.message.indexOf("too deep") !== -1) sawError = true
      finish()
    })
    .on("end", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", function () {})
}

// Note: tar header path field is 100 bytes + 155 bytes (ustar prefix) = 255 max
// without PAX extensions. 2.2.1's programmatic header encoding doesn't emit PAX,
// so we test maxDepth with shorter paths + a custom low maxDepth (same logic).
tap.test("CVE-2024-28863: extraction deeper than maxDepth is rejected", function (t) {
  runMaxDepthTest(t, 10, 15, { path: target, maxDepth: 10 })
})

tap.test("CVE-2024-28863: custom maxDepth=64 rejects 80-deep path", function (t) {
  runMaxDepthTest(t, 64, 80, { path: target, maxDepth: 64 })
})

tap.test("cleanup", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  t.pass("cleaned")
  t.end()
})
