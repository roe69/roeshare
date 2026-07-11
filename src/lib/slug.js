// Custom share-slug rules, shared by share creation and admin rename. A slug
// becomes the share id, which is also the on-disk directory name and resolves at
// the root path /<slug>, so it must be filesystem-safe and not collide with a
// real route or static asset.

export const SLUG_RE = /^[A-Za-z0-9_-]{3,64}$/;

// Rejected because /<slug> would be shadowed by a real route or static asset.
// Also includes Windows-reserved device names: on a Windows-hosted deployment,
// a share's lazily-created upload directory throws on the first chunk write if
// the slug matches one of these, permanently bricking the share.
export const RESERVED_SLUGS = new Set([
	'admin', 'api', 's', 'css', 'js', 'fonts', 'assets', 'favicon', 'robots', 'manifest', 'icon', 'icons', 'android-chrome', 'apple-touch-icon', 'site',
	'con', 'prn', 'aux', 'nul',
	'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
	'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
]);

// Returns an error message for an invalid slug, or null when it is acceptable.
export function slugError(slug) {
	if (!SLUG_RE.test(slug)) return 'Custom link must be 3-64 characters: letters, numbers, hyphens or underscores';
	if (RESERVED_SLUGS.has(slug.toLowerCase())) return 'That custom link is reserved, pick another';
	return null;
}
