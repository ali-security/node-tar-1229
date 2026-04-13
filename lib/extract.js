// give it a tarball and a path, and it'll dump the contents

module.exports = Extract

var tar = require("../tar.js")
  , fstream = require("fstream")
  , inherits = require("inherits")
  , path = require("path")
  , fs = require("fs")
  , stripAbsolutePath = require("./strip-absolute-path.js")

function Extract (opts) {
  if (!(this instanceof Extract)) return new Extract(opts)
  tar.Parse.apply(this)

  if (typeof opts !== "object") {
    opts = { path: opts }
  }

  // better to drop in cwd? seems more standard.
  opts.path = opts.path || path.resolve("node-tar-extract")
  opts.type = "Directory"
  opts.Directory = true

  // similar to --strip or --strip-components
  opts.strip = +opts.strip
  if (!opts.strip || opts.strip <= 0) opts.strip = 0

  // prevent excessively deep nesting of subfolders
  // set to Infinity to remove this restriction
  this._maxDepth = typeof opts.maxDepth === 'number' ? opts.maxDepth : 1024

  this._fst = fstream.Writer(opts)

  this.pause()
  var me = this

  // CVE-2018-20834 fix: Intercept fstream.Writer's "entry" listener
  // Remove hardlinks synchronously AFTER path normalization but BEFORE fstream processes
  // We intercept by wrapping fstream's entry event handling
  var fstEntryListeners = this._fst.listeners("entry")
  // Remove all existing entry listeners from fstream
  this._fst.removeAllListeners("entry")
  // Add our interceptor, then re-add fstream's original listeners
  var meFst = this._fst
  this._fst.on("entry", function (entry) {
    // This runs AFTER the entry handler has normalized the path
    if (entry && entry.type === "File") {
      // Remove hardlink synchronously before fstream processes this entry
      try {
        var fullPath = path.resolve(opts.path, entry.path)
        var stats = fs.lstatSync(fullPath)
        if (stats.nlink > 1) {
          fs.unlinkSync(fullPath)
        }
      } catch (err) {
        // File doesn't exist or other error - that's fine, continue
        if (err.code !== 'ENOENT' && entry.warn) {
          entry.warn('CVE-2018-20834: Could not check/remove hardlink', {
            path: entry.path,
            error: err.message
          })
        }
      }
    }
    // Call fstream's original entry listeners
    for (var i = 0; i < fstEntryListeners.length; i++) {
      fstEntryListeners[i].call(meFst, entry)
    }
  })

  // Hardlinks in tarballs are relative to the root
  // of the tarball.  So, they need to be resolved against
  // the target directory in order to be created properly.
  me.on("entry", function (entry) {
    // if there's a "strip" argument, then strip off that many
    // path components.
    if (opts.strip) {
      var p = entry.path.split("/").slice(opts.strip).join("/")
      entry.path = entry.props.path = p
      if (entry.linkpath) {
        var lp = entry.linkpath.split("/").slice(opts.strip).join("/")
        entry.linkpath = entry.props.linkpath = lp
      }
    }

    // Check path depth after stripping
    if (isFinite(me._maxDepth)) {
      var depthParts = entry.path.split("/").filter(function(part) { return part })
      if (depthParts.length > me._maxDepth) {
        me.emit("error", new Error("Entry path too deep: " + entry.path))
        entry.abort()
        return
      }
    }

    // Normalize path separators for consistent checking
    var p = entry.path.replace(/\\/g, '/')

    // Strip absolute path root BEFORE checking for '..'
    // This ensures that drive-local paths like c:../foo get their root stripped
    // to ../foo, which is then caught by the '..' check below
    var s = stripAbsolutePath(p)
    if (s[0]) {
      entry.path = s[1]
      entry.props.path = s[1]
      p = s[1]
      if (entry.warn) {
        entry.warn('stripping ' + s[0] + ' from absolute path', entry.path)
      }
    }

    // Check for path traversal attempts (after stripping root)
    var parts = p.replace(/\\/g, '/').split('/')
    if (parts.indexOf('..') !== -1) {
      if (entry.warn) {
        entry.warn('TAR_ENTRY_ERROR', 'path contains \'..\'', {
          entry: entry,
          path: p
        })
      }
      return // Skip this entry
    }

    // Resolve the absolute path for this entry using the already-split parts
    // Use parts.join('/') rather than the raw path to avoid drive-relative
    // prefixes like c: confusing path.resolve
    entry.absolute = path.resolve(opts.path, parts.join('/'))

    // Defense in depth: ensure the resolved path doesn't escape the extraction directory
    // This should have been prevented above, but provides additional safety
    var extractPath = path.resolve(opts.path)
    var normalizedExtract = extractPath.replace(/\\/g, '/')
    var normalizedEntry = entry.absolute.replace(/\\/g, '/')

    if (normalizedEntry.indexOf(normalizedExtract + '/') !== 0 &&
      normalizedEntry !== normalizedExtract) {
      if (entry.warn) {
        entry.warn('TAR_ENTRY_ERROR', 'path escaped extraction target', {
          entry: entry,
          path: p,
          resolvedPath: normalizedEntry,
          cwd: normalizedExtract
        })
      }
      return // Skip this entry
    }
    // Sanitize linkpath the same way as path: strip absolute roots and reject '..'
    // Note: tar's Entry object stores linkpath in entry.props.linkpath, not entry.linkpath.
    if (entry.props && entry.props.linkpath) {
      var lp = entry.props.linkpath.replace(/\\/g, '/')
      var ls = stripAbsolutePath(lp)
      if (ls[0]) {
        lp = ls[1]
        entry.linkpath = ls[1]
        entry.props.linkpath = ls[1]
        if (entry.warn) {
          entry.warn('stripping ' + ls[0] + ' from absolute linkpath', lp)
        }
      }
      var lpParts = lp.replace(/\\/g, '/').split('/')
      // Symlinks can legitimately use relative '..' paths, but hardlinks
      // resolve relative to cwd so '..' is always an escape attempt
      if (lpParts.indexOf('..') !== -1 && entry.type === 'Link') {
        if (entry.warn) {
          entry.warn('TAR_ENTRY_ERROR', 'linkpath contains \'..\'', {
            entry: entry,
            path: lp
          })
        }
        // fstream will still process this entry from the pipe, so we can't
        // just `return`. Neutralize the entry: convert to an empty regular
        // file so fstream creates a harmless 0-byte file instead of calling
        // fs.link() with an attacker-controlled path.
        entry.type = 'File'
        entry.props.type = '0'
        entry.size = 0
        entry.linkpath = entry.props.linkpath = ''
        entry.abort()
        return // Skip this entry
      }
    }

    // CVE-2026-26960: Ensure no intermediate path component is a symlink
    // before extracting. fstream follows symlinks, so an attacker could place
    // a symlink entry pointing outside the extraction dir and then place a file
    // entry that traverses through it.
    //
    // Two checks are required because of a timing issue: entries are processed
    // synchronously in our listener but fstream creates files/symlinks async.
    // A lstatSync at this time may return ENOENT for symlinks declared earlier
    // in the stream but not yet written. We therefore also track symlinks we
    // have SEEN in the parse stream and consult that in-memory map.
    me._seenSymlinks = me._seenSymlinks || {}
    function isSymlinkComponent(abs) {
      // Normalize: strip trailing slash, use '/' separators for map lookup
      var key = path.relative(opts.path, abs).replace(/\\/g, '/')
      if (key && me._seenSymlinks[key]) return true
      try { return fs.lstatSync(abs).isSymbolicLink() }
      catch (e) { return false }
    }

    var entryDir = path.resolve(opts.path, path.dirname(entry.path))
    var relDir = path.relative(opts.path, entryDir)
    if (relDir && relDir !== '.') {
      var dirParts = relDir.split(path.sep)
      var checkDir = opts.path
      for (var di = 0; di < dirParts.length; di++) {
        checkDir = path.join(checkDir, dirParts[di])
        if (isSymlinkComponent(checkDir)) {
          if (entry.warn) {
            entry.warn('TAR_SYMLINK_ERROR', 'cannot extract through symbolic link', {
              entry: entry,
              path: checkDir,
              into: entryDir
            })
          }
          entry.abort()
          // Neutralize: convert to empty file to stop fstream.
          entry.type = 'File'
          entry.props.type = '0'
          entry.size = 0
          entry.linkpath = entry.props.linkpath = ''
          return
        }
      }
    }

    if (entry.type === "Link") {
      // Check each parent component of the (pre-rewrite) linkpath against the
      // symlink set. This catches chained-symlink exploits where the linkpath
      // traverses through symlinks declared earlier in the same tar stream.
      var lpRaw = (entry.props.linkpath || '').replace(/\\/g, '/')
      var lpSplit = lpRaw.split('/')
      var linkPrefix = ''
      for (var lpi = 0; lpi < lpSplit.length - 1; lpi++) {
        linkPrefix = linkPrefix ? linkPrefix + '/' + lpSplit[lpi] : lpSplit[lpi]
        if (linkPrefix && me._seenSymlinks[linkPrefix]) {
          if (entry.warn) {
            entry.warn('TAR_SYMLINK_ERROR', 'hardlink target traverses a symbolic link', {
              entry: entry,
              path: linkPrefix,
              linkpath: lpRaw
            })
          }
          entry.type = 'File'
          entry.props.type = '0'
          entry.size = 0
          entry.linkpath = entry.props.linkpath = ''
          entry.abort()
          return
        }
      }

      entry.linkpath = entry.props.linkpath =
        path.join(opts.path, path.join("/", entry.props.linkpath))

      // Also check symlink components in the resolved hardlink target (filesystem)
      var linkTarget = path.resolve(entry.linkpath)
      var relLink = path.relative(opts.path, linkTarget)
      if (relLink) {
        var linkDirParts = relLink.split(path.sep)
        var checkLink = opts.path
        for (var li = 0; li < linkDirParts.length - 1; li++) {
          checkLink = path.join(checkLink, linkDirParts[li])
          if (isSymlinkComponent(checkLink)) {
            if (entry.warn) {
              entry.warn('TAR_SYMLINK_ERROR', 'cannot extract through symbolic link', {
                entry: entry,
                path: checkLink,
                into: linkTarget
              })
            }
            entry.type = 'File'
            entry.props.type = '0'
            entry.size = 0
            entry.linkpath = entry.props.linkpath = ''
            entry.abort()
            return
          }
        }
      }
    }

    if (entry.type === "SymbolicLink") {
      // CVE-2026-26960: also check whether the symlink's own linkpath would
      // traverse through a prior symlink. A chained-symlink exploit can use
      // an intermediate symlink whose linkpath walks out of the extraction
      // root.
      var symDn = path.dirname(entry.path) || ''
      var symLp = (entry.props.linkpath || '').replace(/\\/g, '/')
      var symLpSplit = symLp.split('/')
      var symLpPrefix = ''
      for (var sli = 0; sli < symLpSplit.length - 1; sli++) {
        var part = symLpSplit[sli]
        if (part === '..' || part === '.' || part === '') continue
        // Resolve each prefix relative to the symlink's directory within opts.path
        var candidate = symDn === '.' || !symDn
          ? (symLpPrefix ? symLpPrefix + '/' + part : part)
          : symDn + '/' + (symLpPrefix ? symLpPrefix + '/' + part : part)
        candidate = candidate.replace(/\\/g, '/')
        if (me._seenSymlinks[candidate]) {
          if (entry.warn) {
            entry.warn('TAR_SYMLINK_ERROR', 'symlink target traverses a symbolic link', {
              entry: entry,
              path: candidate,
              linkpath: symLp
            })
          }
          entry.type = 'File'
          entry.props.type = '0'
          entry.size = 0
          entry.linkpath = entry.props.linkpath = ''
          entry.abort()
          return
        }
        symLpPrefix = symLpPrefix ? symLpPrefix + '/' + part : part
      }

      var dn = path.dirname(entry.path) || ""
      var linkpath = entry.props.linkpath
      var target = path.resolve(opts.path, dn, linkpath)
      if (target.indexOf(opts.path) !== 0) {
        linkpath = path.join(opts.path, path.join("/", linkpath))
      }
      entry.linkpath = entry.props.linkpath = linkpath
      // Remember this symlink so later entries can detect traversal through it
      // even before fstream has written it to disk (CVE-2026-26960 race fix).
      var symKey = entry.path.replace(/\\/g, '/').replace(/\/+$/, '')
      me._seenSymlinks[symKey] = true
    }

  })

  this._fst.on("ready", function () {
    me.pipe(me._fst, { end: false })
    me.resume()
  })

  this._fst.on('error', function(err) {
    me.emit('error', err)
  })

  this._fst.on('drain', function() {
    me.emit('drain')
  })

  // this._fst.on("end", function () {
  //   console.error("\nEEEE Extract End", me._fst.path)
  // })

  this._fst.on("close", function () {
    // console.error("\nEEEE Extract End", me._fst.path)
    me.emit("finish")
    me.emit("end")
    me.emit("close")
  })
}

inherits(Extract, tar.Parse)

Extract.prototype._streamEnd = function () {
  var me = this
  if (!me._ended || me._entry) me.error("unexpected eof")
  me._fst.end()
  // my .end() is coming later.
}
