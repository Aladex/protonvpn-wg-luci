# Browser harness

The node suite executes the view and asserts what it renders. It cannot
measure it: widths, wrapping, truncation and overflow only exist once a real
layout engine has run. This directory renders the **real view** into a page a
browser can lay out, so those numbers can be taken and re-taken.

It is not run by CI. It needs a browser and two stylesheets that live on the
router, so it is a tool you run deliberately, not a gate.

## The trap — read this before you measure anything

**The LuCI theme's mobile rules are keyed on `max-device-width`, not
`max-width`.** A narrow desktop window, a narrow iframe and a devtools device
emulation that does not also change the reported *device* width all fail to
trigger them: the form keeps its 180px label column and every number you take
is wrong. A round of this redesign was lost to exactly that.

`emulate-mobile.mjs` re-emits those blocks keyed on `max-width`, and
`frames.html` puts the page in an iframe of the target width so the media
queries evaluate against it. Use both.

## Getting the theme stylesheets

They are not vendored here — they belong to whatever theme the router runs,
and a stale copy would be worse than none:

```sh
scp root@router:/www/luci-static/bootstrap/cascade.css .
scp root@router:/www/luci-static/bootstrap/mobile.css .
node emulate-mobile.mjs mobile.css > mobile-emulated.css
```

## Rendering and measuring

```sh
node render.mjs                 # writes page.html next to this README
python3 -m http.server 8788     # file:// blocks the iframe reads
# then open http://127.0.0.1:8788/luci-app-protonvpn/tests/browser/frames.html
```

`frames.html` exposes `window.measure()`, which returns, per width: the
horizontal overflow, the height of each card, how many grid rows each card
header occupies, and every leaf element whose text is being cut. Drive it from
a devtools console or any CDP client.

Two notes on measuring, both learned the hard way:

* **Count header rows from the grid, not from child positions.** The header is
  `align-items:center`, so its children legitimately have different `top`
  values while sharing one row. `getComputedStyle(line).gridTemplateRows` is
  the honest count.
* **A "before" comparison must use this same harness**, driven against the old
  source. Two different rigs produce two different numbers and prove nothing.
  `PV_VIEW` is what makes that possible:

  ```sh
  git show <ref>:luci-app-protonvpn/htdocs/luci-static/resources/view/\
      protonvpn/overview.js > /tmp/old-overview.js
  PV_VIEW=/tmp/old-overview.js node render.mjs   # renders the OLD view
  node render.mjs                                # renders this checkout
  ```

  `render.mjs` prints which source it used, and exits non-zero if `PV_VIEW`
  points at a file that is not there. The override is passed to `loadView` as
  an option rather than read from the environment inside the harness, so no
  stray `export` can ever point the unit suite somewhere else;
  `harness.test.mjs` pins that it is actually honoured, because this path was
  documented and inert once already.

## Fixtures

`render.mjs` deliberately renders the worst realistic case: a long country
name, a country narrowed to seven cities, Proton's non-ISO `UK` and `XK`, two
codes the server list no longer knows, and a full set of status facts. If you
measure with a short country name you will not see the defect.
