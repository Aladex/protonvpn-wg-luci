// SPDX-License-Identifier: MIT
// What the sign-in modal does to its Continue button, executed against the
// real overview.js (see luci-harness.mjs).
//
// Why this suite exists: the button used to stay enabled and unchanged while
// a sign-in was in flight. A sign-in takes seconds, so the user pressed it
// again, saw nothing again, and pressed again — and after a failure every
// press was a real new attempt. That burst is what Proton's anti-abuse
// answers by temporarily limiting the account, which then reaches the user
// as an error about their account rather than about the button. Feedback and a
// pause are therefore correctness here, not decoration.
//
// Run: node --test luci-app-protonvpn/tests/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadView, makeCtx, findOneClass, findAllClass, text } from './luci-harness.mjs';

const EV = { preventDefault: () => {}, stopPropagation: () => {} };

// Open the sign-in modal with submitCredentials replaced by a spy, so a test
// drives the button without standing up SRP and the RPC round trip.
function openLogin(opts) {
	opts = opts || {};
	const view = loadView();
	const ctx = makeCtx(view.spec, { refs: {} });
	// The real pause is seconds; tests assert that it exists and that it ends,
	// not how long the user waits.
	ctx.LOGIN_RETRY_PAUSE_MS = opts.pause == null ? 25 : opts.pause;
	const attempts = [];
	ctx.submitCredentials = function (fail, render) {
		attempts.push({ fail, render });
		return Promise.resolve();
	};
	ctx.afterLogin = () => Promise.resolve();
	ctx.showLoginModal();
	const modal = view.modals[view.modals.length - 1];
	return { view, ctx, modal, attempts, btn: findOneClass(modal.children, 'pv-login-go') };
}

const press = (btn) => btn.attrs.click(EV);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const spinners = (btn) => findAllClass(btn, 'spinning').length;

test('the sign-in modal builds a Continue button that starts usable', () => {
	const { btn } = openLogin();
	assert.ok(btn, 'the modal renders no identifiable Continue button');
	assert.ok(!btn.disabled, 'the button starts disabled');
	assert.match(text(btn), /Continue/);
	assert.equal(spinners(btn), 0, 'an idle button already shows a spinner');
});

test('pressing Continue disables the button and shows a spinner', () => {
	const { btn, attempts } = openLogin();
	press(btn);
	assert.equal(attempts.length, 1);
	assert.ok(btn.disabled, 'the button stays pressable while the sign-in runs');
	assert.equal(spinners(btn), 1, 'nothing indicates that work is in progress');
	assert.doesNotMatch(text(btn), /Continue/,
		'the label still invites another press');
});

test('further presses while the sign-in is in flight start nothing', () => {
	const { btn, attempts } = openLogin();
	press(btn);
	press(btn);
	press(btn);
	assert.equal(attempts.length, 1, 'a second press started another attempt');
});

test('a successful sign-in restores the button', async () => {
	const view = loadView({ rpc: { set_totp: { ok: true } } });
	const ctx = makeCtx(view.spec, { refs: {}, loginStep: 'totp' });
	ctx.afterLogin = () => Promise.resolve();
	ctx.showLoginModal('totp');
	const modal = view.modals[view.modals.length - 1];
	const btn = findOneClass(modal.children, 'pv-login-go');
	ctx.totpEl.value = '123456';
	press(btn);
	assert.ok(btn.disabled, 'the button is not disabled during the 2FA step');
	await sleep(5);
	assert.ok(!btn.disabled, 'the button stays disabled after a successful sign-in');
	assert.match(text(btn), /Continue/);
	assert.equal(spinners(btn), 0);
});

test('a failed attempt keeps the button out of reach for a visible pause', async () => {
	const { btn, attempts } = openLogin({ pause: 400 });
	press(btn);
	attempts[0].fail('Incorrect login credentials. Please try again.');
	assert.ok(btn.disabled, 'the button is usable again the instant the attempt failed');
	assert.equal(spinners(btn), 0, 'a pause is not work in progress');
	assert.doesNotMatch(text(btn), /Continue/,
		'the pause is invisible: the button still reads Continue');
	assert.match(text(btn), /[0-9]/,
		'the user is not told how long the pause lasts');
	press(btn);
	assert.equal(attempts.length, 1, 'a press during the pause started a new attempt');
});

test('the button comes back by itself once the pause is over', async () => {
	const { btn, attempts } = openLogin({ pause: 25 });
	press(btn);
	attempts[0].fail('Incorrect login credentials. Please try again.');
	await sleep(120);
	assert.ok(!btn.disabled, 'the button never came back');
	assert.match(text(btn), /Continue/);
	press(btn);
	assert.equal(attempts.length, 2, 'the button is dead after the pause');
});

test('the failure message itself still reaches the user', () => {
	const { ctx, attempts, btn } = openLogin();
	press(btn);
	attempts[0].fail('Our systems detected unusual activity targeting your account.');
	assert.match(text(ctx.loginErr), /unusual activity/);
});

test('a refusal that never reached Proton costs no pause', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, { refs: {}, loginStep: 'totp' });
	ctx.LOGIN_RETRY_PAUSE_MS = 400;
	ctx.showLoginModal('totp');
	const btn = findOneClass(view.modals[view.modals.length - 1].children, 'pv-login-go');
	ctx.totpEl.value = 'nonsense';
	press(btn);
	// Nothing was sent, so there is no attempt to be paced — the user has to
	// be able to fix the typo at once.
	assert.ok(!btn.disabled, 'a local typo locked the button');
	assert.match(text(btn), /Continue/);
	assert.match(text(ctx.loginErr), /6-digit/);
});

// The password step is the one the user actually presses Continue on, so it
// needs driving end to end. loadCrypto() short-circuits when window.ProtonSRP
// already exists, which is the seam: the SRP maths has its own suite
// (srp.test.mjs) and is not what is under test here.
function stubSRP() {
	globalThis.window = {
		ProtonSRP: {
			prepareLogin: () => Promise.resolve({
				clientEphemeral: 'CE', clientProof: 'CP', expectedServerProof: 'SP'
			}),
			verifyServerProof: (expected, got) => expected === got
		}
	};
}

const AUTH_INFO = {
	version: 4, salt: 'c2FsdA==', modulus: 'bW9k',
	server_ephemeral: 'c2U=', srp_session: 'sess'
};

test('a successful password step restores the button', async () => {
	stubSRP();
	const view = loadView({ rpc: {
		auth_info: AUTH_INFO,
		auth_finish: { ok: true, twofa: false, server_proof: 'SP' }
	} });
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.afterLogin = () => Promise.resolve();
	ctx.showLoginModal();
	const btn = findOneClass(view.modals[view.modals.length - 1].children, 'pv-login-go');
	ctx.userEl.value = 'user@proton.me';
	ctx.passEl.value = 'secret';
	const running = ctx.submitCredentials(
		(msg) => assert.fail('the sign-in failed: ' + msg), () => {});
	assert.ok(btn.disabled === false || btn.disabled === true);
	await running;
	assert.ok(!btn.disabled, 'the button is left disabled after a successful sign-in');
	assert.match(text(btn), /Continue/);
	assert.equal(spinners(btn), 0, 'the spinner outlives the sign-in');
});

test('a password step that needs a code hands a usable button to the code step', async () => {
	stubSRP();
	const view = loadView({ rpc: {
		auth_info: AUTH_INFO,
		auth_finish: { ok: true, twofa: true, server_proof: 'SP' }
	} });
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.afterLogin = () => Promise.resolve();
	ctx.showLoginModal();
	const btn = findOneClass(view.modals[view.modals.length - 1].children, 'pv-login-go');
	ctx.userEl.value = 'user@proton.me';
	ctx.passEl.value = 'secret';
	press(btn);
	assert.ok(btn.disabled, 'the button was never taken away');
	await new Promise((r) => setTimeout(r, 10));
	assert.equal(ctx.loginStep, 'totp');
	assert.ok(!btn.disabled, 'the two-factor step starts with a dead button');
	assert.match(text(btn), /Continue/);
});

test('a password step Proton refuses lands in the pause, not back on Continue', async () => {
	stubSRP();
	const view = loadView({ rpc: {
		auth_info: { error: 'Incorrect login credentials. Please try again. (Code 8002, HTTP 422)' }
	} });
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 400;
	ctx.afterLogin = () => Promise.resolve();
	ctx.showLoginModal();
	const btn = findOneClass(view.modals[view.modals.length - 1].children, 'pv-login-go');
	ctx.userEl.value = 'user@proton.me';
	ctx.passEl.value = 'secret';
	press(btn);
	await new Promise((r) => setTimeout(r, 10));
	assert.match(text(ctx.loginErr), /Code 8002/,
		"Proton's own message did not reach the user");
	assert.ok(btn.disabled, 'a refused sign-in leaves the button ready for another');
});

// ── the modal is a window onto the sign-in, not the sign-in itself ───────
//
// Closing it used to reset everything: showLoginModal() cleared the cooldown
// timer and forced the button back to 'ready', and Cancel merely hid the
// dialog. So both protections were one Cancel away from gone — measured at
// two real attempts after a close/reopen during an unresolved request, and
// two again after a close/reopen during the pause. The in-flight request and
// the cooldown deadline belong to the sign-in and have to outlive the window.

const cancelOf = (modal) => findOneClass(modal.children, 'pv-login-cancel');
const lastModal = (view) => view.modals[view.modals.length - 1];
const goOf = (modal) => findOneClass(modal.children, 'pv-login-go');

test('closing and reopening does not release an in-flight sign-in', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 400;
	const attempts = [];
	// A request that never settles: the user is staring at the spinner.
	ctx.submitCredentials = function (fail) {
		attempts.push({ fail });
		return new Promise(() => {});
	};
	ctx.showLoginModal();
	press(goOf(lastModal(view)));
	assert.equal(attempts.length, 1);

	cancelOf(lastModal(view)).attrs.click(EV);
	ctx.showLoginModal();
	const btn = goOf(lastModal(view));
	assert.ok(btn.disabled, 'the reopened modal offers a usable button while a sign-in is still running');
	assert.equal(spinners(btn), 1, 'the reopened modal does not show the sign-in in progress');
	press(btn);
	assert.equal(attempts.length, 1, 'close/reopen bought the user a second real attempt');
});

test('closing and reopening does not clear the pause', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 2000;
	const attempts = [];
	ctx.submitCredentials = function (fail) {
		attempts.push({ fail });
		return Promise.resolve();
	};
	ctx.showLoginModal();
	press(goOf(lastModal(view)));
	attempts[0].fail('Incorrect login credentials. Please try again.');

	cancelOf(lastModal(view)).attrs.click(EV);
	ctx.showLoginModal();
	const btn = goOf(lastModal(view));
	assert.ok(btn.disabled, 'reopening handed back a usable button mid-pause');
	assert.match(text(btn), /[0-9]/, 'the reopened modal does not show the remaining pause');
	press(btn);
	assert.equal(attempts.length, 1, 'close/reopen bought the user a second real attempt');
});

test('a pause that survived a reopen still ends by itself', async () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 60;
	const attempts = [];
	ctx.submitCredentials = function (fail) {
		attempts.push({ fail });
		return Promise.resolve();
	};
	ctx.showLoginModal();
	press(goOf(lastModal(view)));
	attempts[0].fail('Incorrect login credentials. Please try again.');
	cancelOf(lastModal(view)).attrs.click(EV);
	ctx.showLoginModal();
	const btn = goOf(lastModal(view));
	await sleep(200);
	assert.ok(!btn.disabled, 'the pause outlived its deadline and never released the button');
	press(btn);
	assert.equal(attempts.length, 2);
});

test('a reopened modal is usable again once nothing is pending', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 400;
	const attempts = [];
	ctx.submitCredentials = function (fail) {
		attempts.push({ fail });
		return Promise.resolve();
	};
	ctx.showLoginModal();
	cancelOf(lastModal(view)).attrs.click(EV);
	ctx.showLoginModal();
	const btn = goOf(lastModal(view));
	assert.ok(!btn.disabled, 'a fresh modal opens with a dead button');
	assert.match(text(btn), /Continue/);
	press(btn);
	assert.equal(attempts.length, 1);
});

test('a late resolution from an abandoned attempt does not touch the current one', async () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 40;
	const attempts = [];
	ctx.submitCredentials = function (fail) {
		attempts.push({ fail });
		return Promise.resolve();
	};
	ctx.showLoginModal();
	const btn = goOf(lastModal(view));
	press(btn);
	attempts[0].fail('Incorrect login credentials. Please try again.');
	await sleep(160);
	press(btn);
	assert.equal(attempts.length, 2, 'the second attempt never started');
	assert.ok(btn.disabled, 'the second attempt is not showing as in flight');
	// The first attempt's callback fires late — a duplicate settle, a catch
	// after a then. It speaks for an attempt the view has moved past.
	attempts[0].fail('Incorrect login credentials. Please try again.');
	assert.ok(btn.disabled,
		'a stale resolution took the running attempt out of its in-flight state');
	assert.equal(spinners(btn), 1, 'a stale resolution replaced the running spinner');
});

test('a sign-in that succeeded leaves the next modal usable', async () => {
	const view = loadView({ rpc: { set_totp: { ok: true } } });
	const ctx = makeCtx(view.spec, { refs: {}, loginStep: 'totp' });
	ctx.LOGIN_RETRY_PAUSE_MS = 400;
	ctx.afterLogin = () => Promise.resolve();
	ctx.showLoginModal('totp');
	const btn = goOf(lastModal(view));
	ctx.totpEl.value = '123456';
	press(btn);
	await sleep(10);
	// Reopening after a finished sign-in must not find the old attempt still
	// marked as on the wire.
	ctx.showLoginModal();
	const again = goOf(lastModal(view));
	assert.ok(!again.disabled, 'a finished sign-in left the next modal blocked');
	assert.match(text(again), /Continue/);
});

test('work after a successful sign-in cannot open a pause the sign-in never earned', async () => {
	const view = loadView({ rpc: { set_totp: { ok: true } } });
	const ctx = makeCtx(view.spec, { refs: {}, loginStep: 'totp' });
	ctx.LOGIN_RETRY_PAUSE_MS = 60000;
	// The sign-in itself worked; what follows it — the server list, the
	// account limits — did not. That must not read as a failed sign-in.
	ctx.afterLogin = () => Promise.reject(new Error('locations unavailable'));
	ctx.showLoginModal('totp');
	const btn = goOf(lastModal(view));
	ctx.totpEl.value = '123456';
	press(btn);
	await sleep(10);
	assert.ok(!btn.disabled,
		'a failure after the sign-in put the Continue button into a retry pause');
	assert.match(text(btn), /Continue/);
	// And it is reported, rather than becoming an unhandled rejection with an
	// empty server list and no explanation.
	const said = (ctx._notices || []).map((n) => n.text).join(' ');
	assert.match(said, /locations unavailable/,
		'the user is signed in with no server list and was told nothing');
});

test('the same is true of the password step', async () => {
	stubSRP();
	const view = loadView({ rpc: {
		auth_info: AUTH_INFO,
		auth_finish: { ok: true, twofa: false, server_proof: 'SP' }
	} });
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 60000;
	ctx.afterLogin = () => Promise.reject(new Error('locations unavailable'));
	ctx.showLoginModal();
	const btn = goOf(lastModal(view));
	ctx.userEl.value = 'user@proton.me';
	ctx.passEl.value = 'secret';
	press(btn);
	await sleep(10);
	assert.ok(!btn.disabled,
		'a failure after the sign-in put the Continue button into a retry pause');
	assert.match((ctx._notices || []).map((n) => n.text).join(' '), /locations unavailable/);
});

// settleLogin()'s staleness check, tested as the contract it is rather than
// through the UI. No path in the page reaches it today — closing the modal
// preserves the in-flight attempt, so a second one cannot start behind the
// first, and a post-sign-in failure is reported by afterLoginReported()
// instead of settling again. It is the same invariant failLogin() enforces
// (which IS driven, above), and it is what keeps that true if either caller
// grows a second settle.
test('settleLogin refuses to speak for an attempt that is not on the wire', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.showLoginModal();
	const btn = goOf(lastModal(view));
	ctx.submitCredentials = () => new Promise(() => {});
	press(btn);
	const current = ctx.loginInFlight;
	assert.ok(current > 0);

	assert.equal(ctx.settleLogin(current - 1), false, 'an older attempt was allowed to settle');
	assert.equal(ctx.loginInFlight, current, 'an older attempt cleared the in-flight marker');
	assert.ok(btn.disabled, 'an older attempt handed the button back');

	assert.equal(ctx.settleLogin(current), true, 'the running attempt could not settle');
	assert.equal(ctx.loginInFlight, 0);
	assert.equal(ctx.settleLogin(current), false, 'the same attempt settled twice');
});

// ── liveness: every attempt that starts must end ─────────────────────────
//
// submit() is the only place that marks an attempt in flight, and
// resumeLoginState() faithfully restores that state when the modal reopens.
// Together those make an unsettled attempt permanent: Continue stays disabled
// reading "Signing in…", and reopening the dialog reproduces the dead button
// instead of clearing it. The only way out is reloading the page.
//
// submitTotp() had exactly that hole — a .then() with no .catch(), so a
// rejected LuCI RPC (transport failure, an rpcd restart, the router dropping
// the connection mid-2FA) settled nothing at all.
//
// So the property under test is not "this one call has a catch". It is: for
// every terminal outcome, on every step, through any modal lifecycle, the
// sign-in comes back. These tests assert that the user can actually try
// again, not merely that a particular callback ran.

// Outcomes that apply to both steps. Each is a way a LuCI RPC really ends.
const FAILING_OUTCOMES = [
	{ name: 'the RPC rejects', answer: () => Promise.reject(new Error('XHR request failed')) },
	{ name: 'the RPC answers with an error', answer: { error: 'Incorrect login credentials.' } },
	{ name: 'the RPC answers with nothing', answer: undefined }
];

// How the user treated the dialog while that was happening.
const LIFECYCLES = [
	{ name: 'with the modal left open', reopen: 0 },
	{ name: 'after closing and reopening it', reopen: 1 },
	{ name: 'after closing and reopening it twice', reopen: 2 }
];

const PAUSE = 40;

function loginCtx(view, step) {
	const ctx = makeCtx(view.spec, { refs: {}, loginStep: step });
	ctx.LOGIN_RETRY_PAUSE_MS = PAUSE;
	ctx.afterLogin = () => Promise.resolve();
	ctx.showLoginModal(step);
	return ctx;
}

// Fill whatever the current step asks for. A reopen rebuilds the inputs
// empty, and submitTotp() clears the code after a failure, so this runs
// before every press.
function fillStep(ctx, step) {
	if (step === 'totp') {
		ctx.totpEl.value = '123456';
	} else {
		ctx.userEl.value = 'user@proton.me';
		ctx.passEl.value = 'secret';
	}
}

// The whole point: after any terminal outcome the sign-in is usable again.
// Not "a callback ran" — the button is alive and a press really starts
// another attempt.
async function assertSignInIsUsableAgain(ctx, view, step, rpcName, label) {
	await sleep(PAUSE * 4);
	const btn = goOf(lastModal(view));
	assert.equal(ctx.loginInFlight, 0, label + ': the attempt is still marked in flight');
	assert.equal(ctx.loginBusy, false, label + ': the sign-in still counts as busy');
	assert.ok(!btn.disabled, label + ': Continue is still disabled');
	assert.equal(spinners(btn), 0, label + ': the spinner never went away');
	assert.match(text(btn), /Continue/, label + ': the button never went back to Continue');

	const before = view.rpcCalls.filter((c) => c.method === rpcName).length;
	fillStep(ctx, step);
	press(btn);
	// The password step reaches its first RPC through loadCrypto(), so the
	// call lands a microtask later than the press.
	await sleep(10);
	assert.equal(view.rpcCalls.filter((c) => c.method === rpcName).length, before + 1,
		label + ': the button looks alive but a press starts nothing');
}

for (const outcome of FAILING_OUTCOMES) {
	for (const cycle of LIFECYCLES) {
		test(`the two-factor step recovers when ${outcome.name}, ${cycle.name}`, async () => {
			const view = loadView({ rpc: { set_totp: outcome.answer } });
			const ctx = loginCtx(view, 'totp');
			fillStep(ctx, 'totp');
			press(goOf(lastModal(view)));
			await sleep(10);
			for (let i = 0; i < cycle.reopen; i++) {
				cancelOf(lastModal(view)).attrs.click(EV);
				ctx.showLoginModal('totp');
			}
			await assertSignInIsUsableAgain(ctx, view, 'totp', 'set_totp',
				`${outcome.name}, ${cycle.name}`);
		});

		test(`the password step recovers when ${outcome.name}, ${cycle.name}`, async () => {
			stubSRP();
			const view = loadView({ rpc: {
				auth_info: AUTH_INFO,
				auth_finish: outcome.answer
			} });
			const ctx = loginCtx(view, 'credentials');
			fillStep(ctx, 'credentials');
			press(goOf(lastModal(view)));
			await sleep(10);
			for (let i = 0; i < cycle.reopen; i++) {
				cancelOf(lastModal(view)).attrs.click(EV);
				ctx.showLoginModal();
			}
			await assertSignInIsUsableAgain(ctx, view, 'credentials', 'auth_info',
				`${outcome.name}, ${cycle.name}`);
		});
	}
}

test('a rejected two-factor RPC says what went wrong', async () => {
	const view = loadView({ rpc: {
		set_totp: () => Promise.reject(new Error('XHR request failed'))
	} });
	const ctx = loginCtx(view, 'totp');
	fillStep(ctx, 'totp');
	press(goOf(lastModal(view)));
	await sleep(10);
	assert.match(text(ctx.loginErr), /XHR request failed/,
		'the sign-in died silently — the user is told nothing at all');
});

// The two remaining ways a step can end without settling. Neither is
// reachable through today's code, and that is the point: submit() is what
// guarantees the attempt ends, so the guarantee must hold for a step that
// misbehaves rather than relying on every callee to remember.
test('a step that throws on its way to a promise still settles the attempt', async () => {
	const view = loadView();
	const ctx = loginCtx(view, 'totp');
	ctx.submitTotp = function () { throw new TypeError('totpEl is null'); };
	fillStep(ctx, 'totp');
	press(goOf(lastModal(view)));
	await sleep(PAUSE * 4);
	assert.equal(ctx.loginInFlight, 0, 'a synchronous throw wedged the sign-in');
	assert.ok(!goOf(lastModal(view)).disabled);
	assert.match(text(ctx.loginErr), /totpEl is null/);
});

test('a step that resolves without settling still settles the attempt', async () => {
	const view = loadView();
	const ctx = loginCtx(view, 'totp');
	ctx.submitTotp = function () { return Promise.resolve(); };
	fillStep(ctx, 'totp');
	press(goOf(lastModal(view)));
	await sleep(PAUSE * 4);
	assert.equal(ctx.loginInFlight, 0, 'a step that forgot to settle wedged the sign-in');
	assert.ok(!goOf(lastModal(view)).disabled);
	assert.notEqual(text(ctx.loginErr), '',
		'the sign-in silently gave up and said nothing');
});

test('the safety net does not fire behind a step that settled properly', async () => {
	const view = loadView({ rpc: { set_totp: { ok: true } } });
	const ctx = loginCtx(view, 'totp');
	ctx.afterLogin = () => Promise.resolve();
	fillStep(ctx, 'totp');
	press(goOf(lastModal(view)));
	await sleep(PAUSE * 4);
	// A successful sign-in must not be followed by a "did not complete"
	// message from the net, nor by a retry pause.
	assert.equal(text(ctx.loginErr), '', 'the net spoke over a successful sign-in');
	assert.equal(ctx.loginCooldownUntil, 0, 'a successful sign-in opened a retry pause');
});

test('a step that rejects without a catch of its own still settles the attempt', async () => {
	// The real steps both catch their own rejections, so this drives the net
	// directly: it is what stops a step that grows a new promise branch — or
	// loses its catch, which is how this round started — from wedging the
	// sign-in.
	const view = loadView();
	const ctx = loginCtx(view, 'totp');
	ctx.submitTotp = function () { return Promise.reject(new Error('rpcd went away')); };
	fillStep(ctx, 'totp');
	press(goOf(lastModal(view)));
	await sleep(PAUSE * 4);
	assert.equal(ctx.loginInFlight, 0, 'a rejected step wedged the sign-in');
	assert.ok(!goOf(lastModal(view)).disabled);
	assert.match(text(ctx.loginErr), /rpcd went away/,
		'the sign-in failed and the user was told nothing');
});

// The other half of the property: while an attempt really is still on the
// wire, every reopen must reproduce the busy state rather than hand back a
// button. The liveness tests above all reopen after the request settled, so
// on their own they say nothing about this direction — which is why the
// mutant that drops the in-flight branch of resumeLoginState() used to take
// only a single test with it.
for (const step of [ 'totp', 'credentials' ]) {
	for (const reopens of [ 1, 2, 3 ]) {
		test(`a pending ${step} attempt is still pending after ${reopens} reopen(s)`, async () => {
			stubSRP();
			const rpc = step === 'totp'
				? { set_totp: () => new Promise(() => {}) }
				: { auth_info: AUTH_INFO, auth_finish: () => new Promise(() => {}) };
			const view = loadView({ rpc });
			const ctx = loginCtx(view, step);
			const rpcName = step === 'totp' ? 'set_totp' : 'auth_finish';
			fillStep(ctx, step);
			press(goOf(lastModal(view)));
			await sleep(10);
			assert.equal(view.rpcCalls.filter((c) => c.method === rpcName).length, 1);

			for (let i = 0; i < reopens; i++) {
				cancelOf(lastModal(view)).attrs.click(EV);
				ctx.showLoginModal(step);
				const btn = goOf(lastModal(view));
				assert.ok(btn.disabled,
					`reopen ${i + 1}: the button came back while the request is still running`);
				assert.equal(spinners(btn), 1,
					`reopen ${i + 1}: the reopened modal does not show the sign-in in progress`);
				assert.equal(ctx.loginInFlight, 1,
					`reopen ${i + 1}: the attempt stopped counting as in flight`);
				fillStep(ctx, step);
				press(btn);
				await sleep(10);
				assert.equal(view.rpcCalls.filter((c) => c.method === rpcName).length, 1,
					`reopen ${i + 1}: a press started a second real attempt`);
			}
		});
	}
}

// And the same breadth for the pause. The deadline is the other piece of
// state a reopen must not clear: it is what stops the burst of real attempts
// that gets an account temporarily limited in the first place.
for (const step of [ 'totp', 'credentials' ]) {
	for (const reopens of [ 1, 2, 3 ]) {
		test(`a pause on the ${step} step survives ${reopens} reopen(s)`, async () => {
			stubSRP();
			const answer = { error: 'Incorrect login credentials.' };
			const rpc = step === 'totp'
				? { set_totp: answer }
				: { auth_info: AUTH_INFO, auth_finish: answer };
			const view = loadView({ rpc });
			const ctx = makeCtx(view.spec, { refs: {}, loginStep: step });
			// Long enough that it cannot lapse while the test reopens.
			ctx.LOGIN_RETRY_PAUSE_MS = 30000;
			ctx.afterLogin = () => Promise.resolve();
			ctx.showLoginModal(step);
			const rpcName = step === 'totp' ? 'set_totp' : 'auth_finish';
			fillStep(ctx, step);
			press(goOf(lastModal(view)));
			await sleep(10);
			assert.equal(view.rpcCalls.filter((c) => c.method === rpcName).length, 1);

			for (let i = 0; i < reopens; i++) {
				cancelOf(lastModal(view)).attrs.click(EV);
				ctx.showLoginModal(step);
				const btn = goOf(lastModal(view));
				assert.ok(btn.disabled, `reopen ${i + 1}: the pause was cleared`);
				assert.match(text(btn), /[0-9]/,
					`reopen ${i + 1}: the reopened modal does not show the remaining pause`);
				fillStep(ctx, step);
				press(btn);
				await sleep(10);
				assert.equal(view.rpcCalls.filter((c) => c.method === rpcName).length, 1,
					`reopen ${i + 1}: a press during the pause started a second real attempt`);
			}
			// Leave no 30s countdown ticking behind the test.
			ctx.loginCooldownUntil = 0;
			clearTimeout(ctx.loginCooldownTimer);
		});
	}
}

// ── a late step must render into the modal that is on screen ─────────────
//
// The sign-in outliving its window was a deliberate decision, and this is the
// other half of it. showLoginModal() used to build a modal-local `body` and a
// `render` closure over it, and submitCredentials held that closure until
// auth_finish came back. Close and reopen while it is still pending, then let
// it resolve with twofa: the code field was rendered into the DETACHED first
// body while the visible modal still showed username and password with
// Continue re-enabled — and loginStep was already 'totp', so pressing the
// visible Continue produced only the local "enter the 6-digit code" refusal,
// issued no RPC, and showed no field to type it into. There was no way
// forward from the screen the user was looking at.
//
// The pending matrices above cannot see this: their pending promise never
// resolves. These resolve it.

function deferred() {
	let settle, fail;
	const promise = new Promise((res, rej) => { settle = res; fail = rej; });
	return { promise, resolve: settle, reject: fail };
}

// Identity, not text: the question is whether this exact node is part of the
// tree the user is looking at.
function containsNode(root, node) {
	if (root === node)
		return true;
	if (root == null || typeof root !== 'object')
		return false;
	if (Array.isArray(root))
		return root.some((c) => containsNode(c, node));
	return containsNode(root.children, node);
}

for (const reopens of [ 1, 2 ]) {
	test(`a pending password step that needs a code transitions the visible modal after ${reopens} reopen(s)`, async () => {
		stubSRP();
		const pending = deferred();
		const view = loadView({ rpc: {
			auth_info: AUTH_INFO,
			auth_finish: () => pending.promise,
			set_totp: { ok: true }
		} });
		const ctx = loginCtx(view, 'credentials');
		ctx.afterLogin = () => Promise.resolve();
		fillStep(ctx, 'credentials');
		press(goOf(lastModal(view)));
		await sleep(10);

		for (let i = 0; i < reopens; i++) {
			cancelOf(lastModal(view)).attrs.click(EV);
			ctx.showLoginModal();
		}

		pending.resolve({ ok: true, twofa: true, server_proof: 'SP' });
		await sleep(20);

		const modal = lastModal(view);
		assert.equal(ctx.loginStep, 'totp');
		assert.match(text(modal.children), /Two-factor code/,
			'the visible modal never moved to the code step');
		assert.doesNotMatch(text(modal.children), /Proton username/,
			'the visible modal is still asking for the password');
		assert.ok(containsNode(modal.children, ctx.totpEl),
			'the code field was rendered into a modal that is not on screen');
		assert.ok(containsNode(modal.children, ctx.loginErr),
			'the error area was moved out of the visible modal');

		// And the screen the user is looking at has to work.
		const btn = goOf(modal);
		assert.ok(!btn.disabled, 'Continue is dead on the code step');
		ctx.totpEl.value = '123456';
		press(btn);
		await sleep(10);
		assert.equal(view.rpcCalls.filter((c) => c.method === 'set_totp').length, 1,
			'pressing Continue on the visible modal submitted nothing');
	});

	test(`Enter in the code field of a modal reopened ${reopens} time(s) submits`, async () => {
		stubSRP();
		const pending = deferred();
		const view = loadView({ rpc: {
			auth_info: AUTH_INFO,
			auth_finish: () => pending.promise,
			set_totp: { ok: true }
		} });
		const ctx = loginCtx(view, 'credentials');
		ctx.afterLogin = () => Promise.resolve();
		fillStep(ctx, 'credentials');
		press(goOf(lastModal(view)));
		await sleep(10);
		for (let i = 0; i < reopens; i++) {
			cancelOf(lastModal(view)).attrs.click(EV);
			ctx.showLoginModal();
		}
		pending.resolve({ ok: true, twofa: true, server_proof: 'SP' });
		await sleep(20);

		// The keydown handler was built by whichever render ran last; it has
		// to drive the sign-in that is actually current.
		ctx.totpEl.value = '123456';
		ctx.totpEl.attrs.keydown({ key: 'Enter' });
		await sleep(10);
		assert.equal(view.rpcCalls.filter((c) => c.method === 'set_totp').length, 1,
			'Enter in the code field of the visible modal submitted nothing');
	});
}

test('a pending step that fails after a reopen reports into the visible modal', async () => {
	stubSRP();
	const pending = deferred();
	const view = loadView({ rpc: { auth_info: AUTH_INFO, auth_finish: () => pending.promise } });
	const ctx = loginCtx(view, 'credentials');
	fillStep(ctx, 'credentials');
	press(goOf(lastModal(view)));
	await sleep(10);
	cancelOf(lastModal(view)).attrs.click(EV);
	ctx.showLoginModal();
	pending.reject(new Error('rpcd went away'));
	await sleep(20);

	const modal = lastModal(view);
	assert.ok(containsNode(modal.children, ctx.loginErr),
		'the error area is not part of the modal on screen');
	assert.match(text(modal.children), /rpcd went away/,
		'the failure is invisible on the screen the user is looking at');
});

test('a pending step that succeeds after a reopen closes the dialog', async () => {
	stubSRP();
	const pending = deferred();
	const view = loadView({ rpc: { auth_info: AUTH_INFO, auth_finish: () => pending.promise } });
	const ctx = loginCtx(view, 'credentials');
	ctx.afterLogin = () => Promise.resolve();
	fillStep(ctx, 'credentials');
	press(goOf(lastModal(view)));
	await sleep(10);
	cancelOf(lastModal(view)).attrs.click(EV);
	ctx.showLoginModal();
	pending.resolve({ ok: true, twofa: false, server_proof: 'SP' });
	await sleep(20);
	assert.equal(lastModal(view).open, false,
		'a sign-in that finished left the reopened dialog on screen');
	assert.equal(ctx.loginInFlight, 0);
});
