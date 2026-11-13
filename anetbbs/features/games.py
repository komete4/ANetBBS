# anetbbs/features/games.py
"""
GameManager — telnet/SSH/rlogin door-game launcher and built-in mini-games.

Door games are pulled from the same Game table the web UI uses, so adding a
game in /admin/games/ makes it instantly available to telnet users too.
"""
import os
import logging

logger = logging.getLogger(__name__)


STOCK_GAME_CATEGORIES = {
    'action': 'Action',
    'classic': 'Classic DOS',
    'puzzle': 'Puzzle',
    'rpg': 'RPG',
    'space': 'Space',
    'strategy': 'Strategy',
    'other': 'Other',
}


def category_label(slug, name, translate):
    """Translate only the stock category names, preserving custom labels."""
    if name == STOCK_GAME_CATEGORIES.get(slug):
        return translate(f'terminal.games.category.{slug}', name)
    return name


class GameManager:
    def __init__(self, session):
        self.session = session

    def _menu_text(self, key, source, **values):
        from .i18n import terminal_label

        return terminal_label(self.session, 'terminal.games.' + key, source, **values)

    async def show_menu(self):
        """Game Center top-level picker (Door Games / Number Guessing).

        A sysop can drop a full replacement at
        data/mods/core/game_center.py (defining an async
        show_game_center_menu(session, game_manager)) to override this
        entirely -- same mechanism and same `chat_manager`-style access
        to this live GameManager instance as data/mods/core/chat_menu.py.
        See core/mods_override.py and docs/35-mods-directory.md.
        """
        from ..core.mods_override import call_core_override
        await call_core_override(
            'game_center', 'show_game_center_menu', self._stock_show_menu,
            self.session, self)

    async def _stock_show_menu(self):
        from .ansi_ui import banner, menu_item, footer, prompt as _p, write_menu_art, ui_width
        while True:
            _w = ui_width(self.session)
            # NodeSpy/anetbbs-monitor heartbeat -- real gap found live
            # (2026-08-28): _heartbeat_node only ever fired from
            # menu_engine.py's generic menu dispatch and _launch() below,
            # so a sysop watching "Doing" saw it frozen at "entered BBS"
            # for anyone browsing the Game Center itself rather than
            # actually playing a door -- GameManager's screens are their
            # own bespoke read_line loops, never routed through
            # menu_engine.py at all.
            if hasattr(self.session, '_heartbeat_node'):
                try:
                    self.session._heartbeat_node(page='games', action='menu: Game Center')
                except Exception:
                    pass
            if not await write_menu_art(self.session, 'game_center'):
                await self.session.clear_screen()
                await self.session.write(banner(self._menu_text('title', 'Game Center'), _w))
                for hk, lbl in (('1', self._menu_text('door_intro', 'Door Games (LORD, TradeWars, etc.)')),
                                ('2', self._menu_text('guess', 'Number Guessing (built-in)')),
                                ('3', self._menu_text('main', 'Return to Main Menu'))):
                    await self.session.write(menu_item(hk, lbl, _w) + '\r\n')
                await self.session.write(footer(_w) + '\r\n')
            choice = (await self.session.read_line(_p(self._menu_text('choice', 'Choice: '))) or '').strip().upper()

            if choice in ('3', 'Q') or not choice:
                break
            elif choice == '1':
                await self.show_door_menu()
            elif choice == '2':
                await self.play_number_guess()

    async def show_door_menu(self):
        """List active door games from the DB and let the user launch one."""
        # Need a Flask app context to query the SQLAlchemy Game table
        from flask import Flask
        from anetbbs.config import get_config
        from anetbbs.models import db, Game, GameCategory
        from .db_scope import transient_app_context

        app = Flask(__name__)
        app.config.from_object(get_config(os.environ.get('FLASK_ENV', 'production')))
        db.init_app(app)

        user_access = (self.session.user or {}).get('access_level') or 10

        with transient_app_context(app):
            games = (Game.query
                     .filter_by(is_active=True)
                     .filter(~Game.game_type.in_(['builtin_web', 'door_dos_browser']))
                     .order_by(Game.sort_order, Game.name)
                     .all())
            # Filter by access level; detach into plain dicts
            game_list = [{
                'id': g.id, 'name': g.name, 'description': g.description,
                'category': g.category or 'other', 'game_type': g.game_type,
                'min_access_level': g.min_access_level or 0,
                'web_game_module': g.web_game_module or '',
                'sort_order': g.sort_order or 0,
            } for g in games if (g.min_access_level or 0) <= user_access]

            # Build slug->name/as_submenu/sort_order maps from DB
            # categories. Order no longer matters here -- category
            # headers now follow the games' own flat sort_order (see the
            # comment further down), not GameCategory.sort_order for
            # WHERE a category appears. GameCategory.sort_order IS still
            # used below as that category's own displayed menu number
            # (see _display_number()).
            cat_rows = GameCategory.query.all()
            localize = getattr(self.session, '_terminal_text', None)
            cat_names = {
                c.slug: category_label(c.slug, c.name, localize) if localize else c.name
                for c in cat_rows
            }
            cat_as_submenu = {c.slug: bool(c.as_submenu) for c in cat_rows}
            cat_sort_order = {c.slug: (c.sort_order or 0) for c in cat_rows}

        # Real bug Jerry hit live, right after the admin drag-and-drop
        # reorder feature shipped for categories: dragging categories
        # into a new order wrote new GameCategory.sort_order values (so
        # the NUMBER shown next to each category changed) but their
        # on-screen POSITION never moved, because the walk below used to
        # iterate game_list directly and plant each as_submenu category's
        # collapsed stand-in line wherever its first member GAME fell in
        # Game.sort_order order -- entirely independent of
        # GameCategory.sort_order. Fixed by pre-computing one combined,
        # globally-number-sorted top-level order up front: each inline
        # (non-submenu) game keeps using its OWN Game.sort_order as
        # before (preserves the earlier "flat numbering spans
        # categories" fix -- see the big comment below), and each
        # as_submenu category contributes exactly ONE entry, positioned
        # by its OWN GameCategory.sort_order instead of by any member
        # game's number. A submenu category always collapses to a single
        # line regardless, so there's no competing "this door's own
        # number must land exactly here" need for it the way there is
        # for an inline game -- safe to let its own sort_order drive
        # position too, not just its label.
        _seen_submenu_slugs = set()
        _combined = []
        for g in game_list:
            slug = g['category']
            if cat_as_submenu.get(slug):
                if slug in _seen_submenu_slugs:
                    continue
                _seen_submenu_slugs.add(slug)
                _combined.append((cat_sort_order.get(slug, 0), 'submenu', slug))
            else:
                _combined.append((g['sort_order'], 'game', g))
        _combined.sort(key=lambda t: t[0])
        top_level_order = [(kind, payload) for (_, kind, payload) in _combined]

        if not game_list:
            await self.session.write(self._menu_text(
                'empty', "\r\n\r\nNo door games are configured yet.\r\n"
                "An admin can add games via the web at /admin/games/.\r\n"))
            await self.session.read_line(self._menu_text('continue', '\r\nPress Enter to continue...'))
            return

        # Real gap Jerry hit live: sort_order used to only control a
        # game's position WITHIN its own category -- categories were
        # always grouped and rendered in their own GameCategory.sort_order,
        # regardless of the individual games' own sort_order values. A
        # sysop numbering every door 1-20 as one flat list (Jerry's own
        # words: "I have all the doors sort orders numbered 1-20")
        # reasonably expects that number to control absolute position in
        # the whole menu -- adding a new door with sort_order 21 landed
        # in the middle instead of at the end, because its CATEGORY
        # happened to sort earlier than categories containing higher-
        # numbered games. Fixed: game_list is already globally ordered by
        # Game.sort_order/name (the query above) -- walk it in that exact
        # order below and insert a category header/boundary wherever the
        # category actually changes, rather than pre-grouping by category
        # first. Category headers are now a side effect of the flat walk,
        # not the primary sort key.
        # grouped is still needed for as_submenu categories -- a section
        # needs ALL of that category's games (wherever they fall in the
        # flat order), not just the contiguous run at first sight.
        grouped = {}
        for g in game_list:
            grouped.setdefault(g['category'], []).append(g)

        from .ansi_ui import write_menu_art, ui_width
        # Bold+base (1;3X), not bare aixterm 90-97 -- MagiTerm/NetRunner/
        # PuTTY don't recognize 90-97 and silently drop the color.
        CYAN = '\x1b[1;36m'; WHT = '\x1b[1;37m'; YEL = '\x1b[1;33m'
        GRN = '\x1b[1;32m'; BOLD = '\x1b[1m'; RESET = '\x1b[0m'; DIM = '\x1b[37m'
        while True:
            _iw = ui_width(self.session)
            if hasattr(self.session, '_heartbeat_node'):
                try:
                    self.session._heartbeat_node(page='games:doors', action='menu: Door Games')
                except Exception:
                    pass
            # Two columns per category row -- one game per line ran off the
            # bottom of a real 24-row terminal once the door count passed
            # ~10 (Jerry: "once you get so many, you cant see them all...
            # I had to use the syncterm scroll back to see the top games").
            # Column width leaves room for a right-hand gutter between the
            # two columns; the [game_type] tag from the old single-column
            # layout is dropped here (implementation detail, not something
            # a player picking a game needs) to make room.
            _cols    = 2
            _col_w   = max(20, (_iw // _cols) - 2)
            # Maps the DISPLAYED/typed number -> either a game dict
            # (launch it directly) or a ('submenu', slug, cat_name) tuple
            # (a category with as_submenu=True: drill into a second-level
            # menu of just that category's games instead of expanding
            # inline). The number itself is each game's own Game.sort_order
            # (or, for a submenu category stand-in, that category's own
            # GameCategory.sort_order) -- NOT a recomputed rank. Real bug
            # fixed here: numbering used to be a fresh `num = 1; num += 1`
            # counter walked every redraw, so adding/removing/reordering
            # ANY game anywhere shifted every later game's displayed
            # number, silently invalidating a sysop's own hand-drawn ANSI
            # door-menu art that hardcodes option numbers (reported live:
            # "I have had to remove my ansi menus multiple times because
            # the numbers change"). A game's own number now only changes
            # when ITS OWN sort_order is changed. First-claimant-wins on a
            # genuine sort_order collision (`setdefault`) -- the admin UI
            # warns about collisions on save so they're rare in practice,
            # but this never crashes if one slips through; the colliding
            # entry still renders, it's just unreachable by that number
            # until the collision is fixed. Rebuilt every redraw since
            # it's cheap and keeps numbering in sync with what's actually
            # on screen.
            by_number = {}
            if self.session.term_mode == 'enhanced':
                # Real clickable buttons for the door-games category
                # list -- Jerry's explicit ask, same treatment the main
                # menu and login screen already got. This menu is
                # read_line()-driven (a choice can be multi-digit, e.g.
                # "16"), unlike those single-keystroke menus --
                # encode_menu()'s 'send' override (the number/letter
                # plus a trailing '\r') makes a click submit exactly
                # the way a typed choice + Enter would, so the
                # read_line()/numbered[] dispatch logic below needs
                # zero changes to support it.
                from .enhanced_protocol import encode_menu
                item_list = []
                for kind, payload in top_level_order:
                    if kind == 'submenu':
                        slug = payload
                        cat_name = cat_names.get(slug, slug.capitalize())
                        count = len(grouped[slug])
                        plural = self._menu_text('one', 'door') if count == 1 else self._menu_text('many', 'doors')
                        num = cat_sort_order.get(slug, 0)
                        item_list.append((str(num), f'{cat_name} ({count} {plural})',
                                          '', '', f'{num}\r'))
                        by_number.setdefault(num, ('submenu', slug, cat_name))
                        continue
                    g = payload
                    num = g['sort_order']
                    item_list.append((str(num), g['name'], '', '', f'{num}\r'))
                    by_number.setdefault(num, g)
                item_list.append(('Q', self._menu_text('return', 'Return'), '', '', 'Q\r'))
                self.session._enhanced_vt_state = None
                self.session.writer.write(
                    encode_menu(self._menu_text('doors', 'Door Games'), item_list).encode('utf-8'))
                await self.session._drain_protected()
                self.session._enhanced_menu_active = True
            elif not await write_menu_art(self.session, 'door_games'):
                await self.session.clear_screen()
                hbar = '═' * _iw
                title = self._menu_text('doors', 'Door Games').center(_iw)
                await self.session.write(f"\r\n{BOLD}{CYAN}{hbar}{RESET}\r\n")
                await self.session.write(f"{WHT}{title}{RESET}\r\n")
                await self.session.write(f"{BOLD}{CYAN}{hbar}{RESET}\r\n")
                prev_slug = None
                cells = []

                async def _flush_cells():
                    for i in range(0, len(cells), _cols):
                        row = '  '.join(cells[i:i + _cols])
                        await self.session.write(f"  {row}\r\n")
                    cells.clear()

                for kind, payload in top_level_order:
                    if kind == 'submenu':
                        slug = payload
                        await _flush_cells()
                        cat_name = cat_names.get(slug, slug.capitalize())
                        cat_games = grouped[slug]
                        count = len(cat_games)
                        plural = self._menu_text('one', 'door') if count == 1 else self._menu_text('many', 'doors')
                        num = cat_sort_order.get(slug, 0)
                        await self.session.write(
                            f"  {YEL}{num:2d}{DIM}. {GRN}{BOLD}{cat_name}{RESET}"
                            f"{DIM} -> ({count} {plural}){RESET}\r\n")
                        by_number.setdefault(num, ('submenu', slug, cat_name))
                        prev_slug = slug
                        continue
                    g = payload
                    slug = g['category']
                    if slug != prev_slug:
                        await _flush_cells()
                        cat_name = cat_names.get(slug, slug.capitalize())
                        label = f"  ─── {cat_name} "
                        fill = '─' * max(0, _iw - len(label))
                        await self.session.write(f"{BOLD}{CYAN}{label}{fill}{RESET}\r\n")
                        prev_slug = slug
                    num = g['sort_order']
                    name_col = g['name'][:_col_w - 5]
                    cells.append(
                        f"{YEL}{num:2d}{DIM}. {GRN}{name_col:<{_col_w - 5}}{RESET}")
                    by_number.setdefault(num, g)
                await _flush_cells()
                await self.session.write(f"  {YEL}Q{DIM}. {GRN}{self._menu_text('return', 'Return')}{RESET}\r\n")
                await self.session.write(f"{BOLD}{CYAN}{hbar}{RESET}\r\n\r\n")
            else:
                # write_menu_art drew a custom screen -- by_number still
                # needs to be built (same numbers the loops above would
                # assign) so input parsing matches whatever the custom
                # art actually shows.
                for kind, payload in top_level_order:
                    if kind == 'submenu':
                        slug = payload
                        num = cat_sort_order.get(slug, 0)
                        by_number.setdefault(
                            num, ('submenu', slug, cat_names.get(slug, slug.capitalize())))
                        continue
                    g = payload
                    by_number.setdefault(g['sort_order'], g)

            choice = await self.session.read_line(self._menu_text('pick', 'Pick a game (number or Q): '))
            if not choice or choice.lower() == 'q':
                return
            try:
                entry = by_number.get(int(choice))
                if entry is not None:
                    if isinstance(entry, tuple) and entry[0] == 'submenu':
                        _, slug, cat_name = entry
                        await self._show_category_submenu(slug, cat_name, grouped[slug])
                    else:
                        await self._launch(entry)
                    continue
            except ValueError:
                pass
            await self.session.write(self._menu_text('invalid', '\r\nInvalid choice.\r\n'))

    async def _show_category_submenu(self, slug, cat_name, games):
        """Second-level door menu for a single as_submenu=True category --
        same flat numbered/2-column rendering as the top-level menu's
        inline category blocks, just scoped to one category and with
        'B'/'Q' returning to the parent door menu instead of the main
        menu. Deliberately one level deep only -- a submenu category's
        own games are always shown flat here, no further nesting.

        Paginated: a category with more entries than fit on one screen
        (real live bug reported 2026-09-01 -- a 100+-game category from
        the A-Net Game Server bulk import ran off the bottom of a fixed-
        height terminal with no way to see the rest) shows one page at a
        time with [N]ext/[P]rev navigation, matching this codebase's
        existing --MORE-- pagination convention (see bbs_ui.py's
        _page_lines). Numbering stays absolute across pages (game #47 is
        always #47, whichever page it's currently showing on) so a
        remembered number always picks the same game.

        Custom art: checked under the slot name `door_games_<category-
        slug>` (e.g. a category with slug "synchronet-doors" looks for
        data/text/menus/door_games_synchronet-doors.ans), mirroring the
        top-level door menu's own `door_games` slot -- falls back to
        this generated layout if no matching file exists. Custom art is
        only ever shown for page 1 (art is a fixed, hand-drawn screen --
        there's no per-page variant of it), later pages always use the
        generated layout. See docs/04-ansi-screens.md's slot-names
        reference and docs/14-door-games.md's "Categories and submenu
        sections"."""
        from .ansi_ui import write_menu_art, ui_width, ui_height
        CYAN = '\x1b[1;36m'; WHT = '\x1b[1;37m'; YEL = '\x1b[1;33m'
        GRN = '\x1b[1;32m'; BOLD = '\x1b[1m'; RESET = '\x1b[0m'; DIM = '\x1b[37m'
        art_slot = f'door_games_{slug}'
        _cols = 2
        # Chrome around the game grid on the generated layout: top hbar,
        # title, hbar, (footer nav line), "B. Back" line, bottom hbar,
        # blank line, prompt line -- 8 fixed lines not available for
        # game rows.
        _chrome_rows = 8
        # Displayed/typed number is each game's own Game.sort_order, not
        # a recomputed page-relative rank -- same fix and same rationale
        # as show_door_menu()'s own `by_number` (see its comment). Built
        # once since `games` is this whole category's fixed member list,
        # not just the current page.
        by_number = {}
        for g in games:
            by_number.setdefault(g['sort_order'], g)
        page = 0
        while True:
            _iw = ui_width(self.session)
            _ih = ui_height(self.session)
            if hasattr(self.session, '_heartbeat_node'):
                try:
                    self.session._heartbeat_node(page='games:doors', action=f'menu: {cat_name}')
                except Exception:
                    pass
            _col_w = max(20, (_iw // _cols) - 2)
            rows_per_page = max(3, _ih - _chrome_rows)
            page_size = rows_per_page * _cols
            total_pages = max(1, (len(games) + page_size - 1) // page_size)
            page = max(0, min(page, total_pages - 1))
            start = page * page_size
            end = min(start + page_size, len(games))
            page_games = games[start:end]

            if self.session.term_mode == 'enhanced':
                # Same treatment as the top-level door menu (see
                # show_door_menu()'s own comment) -- real clickable
                # buttons, multi-digit/letter choices submitted via
                # encode_menu()'s 'send' override so the read_line()
                # dispatch below needs no changes.
                from .enhanced_protocol import encode_menu
                item_list = [(str(g['sort_order']), g['name'], '', '',
                             f"{g['sort_order']}\r")
                            for g in page_games]
                if total_pages > 1:
                    if page > 0:
                        item_list.append(('P', self._menu_text('previous', 'Prev page'), '', '', 'P\r'))
                    if page < total_pages - 1:
                        item_list.append(('N', self._menu_text('next', 'Next page'), '', '', 'N\r'))
                item_list.append(('B', self._menu_text('back', 'Back'), '', '', 'B\r'))
                page_title = cat_name
                if total_pages > 1:
                    page_title = self._menu_text('page_title', '{category} (page {page}/{total})',
                        category=cat_name, page=page + 1, total=total_pages)
                self.session._enhanced_vt_state = None
                self.session.writer.write(
                    encode_menu(page_title, item_list).encode('utf-8'))
                await self.session._drain_protected()
                self.session._enhanced_menu_active = True
            elif page > 0 or not await write_menu_art(self.session, art_slot):
                await self.session.clear_screen()
                hbar = '═' * _iw
                title = cat_name.center(_iw)
                await self.session.write(f"\r\n{BOLD}{CYAN}{hbar}{RESET}\r\n")
                await self.session.write(f"{WHT}{title}{RESET}\r\n")
                await self.session.write(f"{BOLD}{CYAN}{hbar}{RESET}\r\n")
                cells = []
                for g in page_games:
                    name_col = g['name'][:_col_w - 5]
                    cells.append(
                        f"{YEL}{g['sort_order']:2d}{DIM}. {GRN}{name_col:<{_col_w - 5}}{RESET}")
                for i in range(0, len(cells), _cols):
                    row = '  '.join(cells[i:i + _cols])
                    await self.session.write(f"  {row}\r\n")
                if total_pages > 1:
                    page_label = self._menu_text(
                        'page_range', 'page {page}/{total} ({start}-{end} of {count})',
                        page=page + 1, total=total_pages, start=start + 1,
                        end=end, count=len(games))
                    await self.session.write(f"  {DIM}-- {page_label} --{RESET}\r\n")
                    nav = []
                    if page > 0:
                        nav.append(f"{YEL}P{DIM}. {GRN}{self._menu_text('previous', 'Prev page')}{RESET}")
                    if page < total_pages - 1:
                        nav.append(f"{YEL}N{DIM}. {GRN}{self._menu_text('next', 'Next page')}{RESET}")
                    if nav:
                        await self.session.write("  " + "   ".join(nav) + "\r\n")
                await self.session.write(f"  {YEL}B{DIM}. {GRN}{self._menu_text('back', 'Back')}{RESET}\r\n")
                await self.session.write(f"{BOLD}{CYAN}{hbar}{RESET}\r\n\r\n")

            # Real live UI bug: this used to always say "number, N/P, or
            # B" even on a single-page category (e.g. a 13-game InterBBS
            # network list) where there's no N/P navigation to speak of
            # -- the "-- page X/Y --" line and Prev/Next hints above are
            # already correctly hidden for total_pages == 1 (see above),
            # the prompt text just never matched.
            prompt = (self._menu_text('pick_pages', 'Pick a game (number, N/P, or B): ') if total_pages > 1
                      else self._menu_text('pick_back', 'Pick a game (number or B): '))
            choice = (await self.session.read_line(prompt) or '').strip()
            if not choice or choice.lower() in ('b', 'q'):
                return
            low = choice.lower()
            if low == 'n' and page < total_pages - 1:
                page += 1
                continue
            if low == 'p' and page > 0:
                page -= 1
                continue
            try:
                entry = by_number.get(int(choice))
                if entry is not None:
                    await self._launch(entry)
                    continue
            except ValueError:
                pass
            await self.session.write(self._menu_text('invalid', '\r\nInvalid choice.\r\n'))

    async def _launch(self, game_dict):
        """Launch a door game and bridge it to this session.
        DOS games use the TCP-nullmodem path (works with vanilla DOSBox).
        builtin_python games are called directly (no subprocess).
        Other game types use the PTY path."""

        # "Who's on" detail: menu_engine.py's dispatch only knows the user
        # picked the generic "games" action -- this is the one place that
        # knows WHICH game, so it's the natural spot to set the finer-
        # grained presence page Jerry asked for ("playing Lord" instead of
        # just "in games").
        presence = getattr(self.session, 'presence', None)
        if presence is not None:
            try:
                presence.set_page(f'games:{game_dict.get("name", "?")}')
            except Exception:
                pass
        if hasattr(self.session, '_heartbeat_node'):
            try:
                self.session._heartbeat_node(action=f'door: {game_dict.get("name", "?")}')
            except Exception:
                pass

        import time as _time
        _launch_started = _time.monotonic()
        if hasattr(self.session, '_log_activity'):
            try:
                self.session._log_activity('door_played', game_dict.get('name', '?'))
            except Exception:
                pass

        # builtin_python — pure Python game, no subprocess or door runner needed.
        if game_dict.get('game_type') == 'builtin_python':
            module_path = game_dict.get('web_game_module', '')
            if not module_path:
                await self.session.write("\r\nGame has no module configured.\r\n")
                return
            try:
                import importlib
                mod_name, func_name = (module_path.rsplit(':', 1)
                                       if ':' in module_path
                                       else (module_path, 'launch'))
                mod = importlib.import_module(mod_name)
                fn  = getattr(mod, func_name)
                username = (self.session.user or {}).get('username', 'player')
                # Real bug found live (SSH): a builtin_python game that
                # touches the database (MudCharacter.query, etc. -- the
                # first one that actually needed this) crashed with
                # "Working outside of application context" the instant
                # it queried, since this in-process path never pushed
                # one -- the WEB UI's separate subprocess bridge
                # (builtin_runner.py) has the identical fix for the
                # identical reason; this is that same gap in the OTHER
                # launch path. Same throwaway-Flask-app shape this
                # function already builds further down for the
                # non-builtin_python branch.
                from flask import Flask as _Flask
                from anetbbs.config import get_config as _get_config
                from anetbbs.models import db as _db
                from .db_scope import transient_app_context as _tac
                _app = _Flask(__name__)
                _app.config.from_object(_get_config(os.environ.get('FLASK_ENV', 'production')))
                _db.init_app(_app)
                with _tac(_app):
                    await fn(self.session, username)
            except Exception as exc:
                logger.exception('builtin_python game error: %s', exc)
                await self.session.write(f"\r\nError launching game: {exc}\r\n")
                await self.session.read_line("\r\nPress Enter...")
            finally:
                if presence is not None:
                    try:
                        presence.set_page('games')
                    except Exception:
                        pass
                if hasattr(self.session, '_log_activity'):
                    try:
                        _elapsed = int(_time.monotonic() - _launch_started)
                        self.session._log_activity(
                            'door_exited',
                            f'{game_dict.get("name", "?")} ({_elapsed}s)')
                    except Exception:
                        pass
            return

        from flask import Flask
        from anetbbs.config import get_config
        from anetbbs.models import db, Game
        from ..games.door_runner import (play_door_game_telnet, play_rlogin_telnet,
                                         play_telnet_terminal)
        from .db_scope import transient_app_context

        app = Flask(__name__)
        app.config.from_object(get_config(os.environ.get('FLASK_ENV', 'production')))
        db.init_app(app)

        with transient_app_context(app):
            g = Game.query.get(game_dict['id'])
            if g is None:
                await self.session.write("\r\nGame disappeared from the catalog.\r\n")
                return

        # door_rlogin / door_telnet are remote game-server types — no
        # local subprocess, just a TCP connection bridged to the user's
        # terminal. Everything else goes through the unified launch path.
        gtype = game_dict.get('game_type')
        if gtype == 'door_rlogin':
            launcher = play_rlogin_telnet
        elif gtype == 'door_telnet':
            launcher = play_telnet_terminal
        else:
            launcher = play_door_game_telnet

        try:
            await launcher(
                game=g,
                user=self.session.user,
                session=self.session,
            )
        except Exception as exc:
            logger.exception('Door game error: %s', exc)
            await self.session.write(f"\r\nError launching game: {exc}\r\n")
            await self.session.read_line("\r\nPress Enter...")
        finally:
            if presence is not None:
                try:
                    presence.set_page('games')
                except Exception:
                    pass
            if hasattr(self.session, '_log_activity'):
                try:
                    _elapsed = int(_time.monotonic() - _launch_started)
                    self.session._log_activity(
                        'door_exited',
                        f'{game_dict.get("name", "?")} ({_elapsed}s)')
                except Exception:
                    pass

    async def play_number_guess(self):
        """Built-in number guessing — no door, pure session I/O."""
        import random
        if hasattr(self.session, '_heartbeat_node'):
            try:
                self.session._heartbeat_node(page='games:number-guess',
                                             action='playing: Number Guessing')
            except Exception:
                pass
        number = random.randint(1, 100)
        tries = 0

        await self.session.write("\r\nI'm thinking of a number between 1 and 100\r\n")

        while True:
            guess = await self.session.read_line("Your guess: ")
            try:
                guess = int(guess)
                tries += 1

                if guess < number:
                    await self.session.write("Too low!\r\n")
                elif guess > number:
                    await self.session.write("Too high!\r\n")
                else:
                    await self.session.write(f"\r\nCongratulations! You got it in {tries} tries!\r\n")
                    break
            except ValueError:
                await self.session.write("Please enter a valid number\r\n")

        await self.session.read_line("\r\nPress Enter to continue...")


def resolve_sort_order_collisions():
    """Idempotent self-healing pass, run on every boot (same convention
    as every other backfill/seed step in web_app.py's own
    _create_default_data()).

    GAMES inside an as_submenu=True category's own submenu page: real
    live feedback, confirmed directly -- Jerry has no existing hand-
    drawn ANSI art for any category submenu page ("I do not have the
    sub-menus ansi because the numbers kept changing"), specifically
    BECAUSE this class of bug made it pointless to build one. With no
    art to protect, a submenu's games get the exact same treatment
    categories themselves already get below: always resequenced to a
    clean 1, 2, 3, ... run on every boot, not just when a literal
    collision exists -- otherwise a category that happened to already
    be collision-FREE-but-gappy (e.g. "0, 10, 20, 30, ..." -- the
    result of an EARLIER version of this same function, which only
    bumped genuine duplicates) would never reach a clean state at all,
    confirmed live: ADULT and CHAT/Apps/Other stayed at "0, 10, 20..."
    forever while ADVENTURE (still a live collision) got fixed, an
    inconsistent, confusing result across categories a sysop is
    looking at side by side.

    GAMES NOT inside an as_submenu category (an inline category's own
    games, shown directly at the top level, or a game with no category
    at all) keep the OLD, more conservative collision-only rule
    instead: a sysop's own deliberately-chosen number can be hardcoded
    into the TOP-LEVEL door-menu art screen (see show_door_menu()'s own
    big comment) -- and unlike submenu pages, Jerry has NOT said that
    top-level art doesn't currently exist, so this stays narrow there:
    only a GENUINE duplicate gets touched, and even then only the
    duplicates are bumped to a free value, not a full resequence.

    CATEGORIES: unlike games, a category's own number isn't something
    a sysop hardcodes into per-door ANSI art -- it's a short,
    sysop-curated navigational list, and real live feedback (repeated
    across several rounds: "numbers should start at 1") made clear
    categories don't carry games' same "never reshuffle" expectation.
    So every as_submenu=True category that currently shows a numbered
    stand-in line at all (has at least one visible active game -- an
    empty/invisible category would otherwise silently waste a number
    the same way an inline category used to, before that was fixed)
    gets resequenced to a clean 1, 2, 3, ... run on every boot,
    preserving whatever relative order the sysop already dragged them
    into -- this only ever cleans up the NUMBER label, drag-and-drop
    still fully controls the actual order."""
    from ..models import db, Game, GameCategory
    changed = False

    # Same exact filter show_door_menu() itself uses to build game_list
    # -- real bug found live: an earlier version of this function used
    # a plain is_active=True query, which still counted a category
    # whose only games were builtin_web/door_dos_browser (types that
    # NEVER appear in the terminal Door Games menu at all, by design)
    # as "visible", handing it a number that then silently vanished
    # from the sequence a sysop actually sees on screen -- e.g. "2, 3,
    # 4, ... 12, [missing 13], 14, ..." for exactly the categories/
    # games this mismatch affected.
    active_games = (Game.query.filter_by(is_active=True)
                    .filter(~Game.game_type.in_(['builtin_web', 'door_dos_browser']))
                    .order_by(Game.sort_order, Game.name).all())
    submenu_cat_slugs = {c.slug for c in GameCategory.query.filter_by(as_submenu=True).all()}
    games_by_category = {}
    for g in active_games:
        games_by_category.setdefault(g.category or 'other', []).append(g)
    for cat_slug, games in games_by_category.items():
        # games is already ordered by (sort_order, name) from the query
        # above -- resequencing in that same order preserves whatever
        # relative position already existed, only the NUMBER changes.
        if cat_slug in submenu_cat_slugs:
            for i, g in enumerate(games, start=1):
                if g.sort_order != i:
                    g.sort_order = i
                    changed = True
            continue
        orders = [g.sort_order or 0 for g in games]
        has_collision = len(set(orders)) != len(orders)
        if not has_collision:
            continue
        seen = set()
        next_free = max(orders)
        for g in games:
            so = g.sort_order or 0
            if so in seen:
                next_free += 10
                g.sort_order = next_free
                changed = True
            else:
                seen.add(so)

    active_cat_slugs = {g.category for g in active_games}
    numbered_cats = [c for c in GameCategory.query.filter_by(as_submenu=True)
                     .order_by(GameCategory.sort_order, GameCategory.name).all()
                     if c.slug in active_cat_slugs]
    for i, c in enumerate(numbered_cats, start=1):
        if c.sort_order != i:
            c.sort_order = i
            changed = True

    if changed:
        db.session.commit()
    return changed
