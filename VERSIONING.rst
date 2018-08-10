#################
Versioning Policy
#################

We will use a three-part X.Y.Z (Major.Minor.Patch) versioning definition with the following meanings.

* X (Major) version changes cover changes to the code-base that are expected to break backwards compatibility.
* Y (Minor) version changes cover moderate changes. These include significant (non-breaking) feature additions and might contain changes which break backwards compatability. If there are breaking changes, they will be explicitly stated in the release notes.
* Z (Patch) version changes cover small changes. They will not break backwards compatibility.

***********************
What this means for you
***********************

We definitely recommend always running on the most recent version of our code. This is how we recommend doing so. 

* X changes will likely require dedicated time and work to incorporate into your code-base.
* Y changes are unlikely to require significant (or any) work to incorporate. If you have good unit and integration tests, they can likely be picked up in an automated manner.
* Z changes should not require any changes to your code and can be picked up in an automated manner. (Good unit and integration tests are always recommended.)

