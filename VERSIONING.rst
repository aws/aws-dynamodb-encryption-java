*****************
Versioning Policy
*****************

We use a three-part X.Y.Z (Major.Minor.Patch) versioning definition as follows:

* **X (Major)** version changes are significant and expected to break backwards compatibility.
* **Y (Minor)** version changes are moderate changes. These include:

  * Significant non-breaking feature additions.
  * Potentially breaking changes. Any such changes will be explicitly stated in the release notes.
  * Changes to our package's declared dependency versions.

* **Z (Patch)** version changes are small changes. They will not break backwards compatibility.

  * Where possible, we will advise of upcoming breaking changes with warnings in a Z release.

What this means for you
=======================

We recommend running the most recent version. Here are our suggestions for managing updates:

* Expect X changes to require effort to incorporate.
* Expect Y changes not to require significant effort to incorporate.

  * If you have good unit and integration tests, these changes are generally safe to pick up automatically.

* Expect Z changes not to require changes to your code. Z changes are intended to be picked up automatically.

  * Good unit and integration tests are always recommended.

