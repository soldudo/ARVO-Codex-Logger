"""Add the patch_verification table and backfill the pre-capture verdicts.

Rerunnable and non-destructive: CREATE TABLE IF NOT EXISTS plus an idempotent
backfill guarded on (run_id, attempt=0). Nothing is dropped or altered.

    python patch_verification_upgrade.py            # migrate + backfill
    python patch_verification_upgrade.py --no-backfill
    python patch_verification_upgrade.py --dry-run

Backfilled rows are attempt=0 so analysis can exclude verdicts that predate
capture. Per analysis/EVALUATION_PIPELINE.md, columns that were not recorded at
the time stay NULL rather than being guessed: compile_rc, patch_rc, patch_text
and all provenance are unknowable for these rows.
"""
import argparse
import logging
import sqlite3
import sys

from schema import PATCH_VERIFICATION_DDL, PATCH_VERIFICATION_INDEX_DDL

logger = logging.getLogger(__name__)

DB_PATH = 'arvo_loc_runs.db'


# Columns added after the table first shipped. Applied with ALTER only when
# absent, so an existing database catches up and a fresh one created from
# PATCH_VERIFICATION_DDL already has them.
ADDED_COLUMNS = {
    'transcript_path': 'TEXT',
}


def migrate(conn: sqlite3.Connection) -> None:
    conn.execute(PATCH_VERIFICATION_DDL)
    conn.execute(PATCH_VERIFICATION_INDEX_DDL)

    existing = {r[1] for r in conn.execute('PRAGMA table_info(patch_verification)')}
    for col, col_type in ADDED_COLUMNS.items():
        if col not in existing:
            conn.execute(f'ALTER TABLE patch_verification ADD COLUMN {col} {col_type}')
            logger.info(f'added column patch_verification.{col}')

    conn.commit()
    logger.info('patch_verification table and index present')


def backfill(conn: sqlite3.Connection, dry_run: bool = False) -> int:
    """Copy the existing adjudicated patch_data rows in as attempt=0.

    patch_data.patch_crash_log holds stdout and stderr concatenated, so it maps
    to poc_stdout with poc_stderr left NULL. compile_errors held stderr only.

    A database with no patch_data table is a fresh one with nothing to carry
    over, so that is a skip rather than an error.
    """
    for table in ('patch_data', 'runs', 'arvo'):
        if not conn.execute("SELECT name FROM sqlite_master WHERE type='table' "
                            "AND name = ?", (table,)).fetchone():
            logger.info(f'backfill: no {table} table, skipping (fresh database)')
            return 0

    rows = conn.execute('''
        SELECT p.run_id, p.is_crash_resolved, p.patch_crash_log, p.compile_errors,
               a.crash_output
        FROM patch_data p
        JOIN runs r ON r.run_id = p.run_id
        LEFT JOIN arvo a ON a.localId = r.vuln_id
        WHERE p.is_crash_resolved IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM patch_verification v
                          WHERE v.run_id = p.run_id AND v.attempt = 0)
    ''').fetchall()

    if not rows:
        logger.info('backfill: nothing to do')
        return 0

    if dry_run:
        logger.info(f'backfill: would insert {len(rows)} legacy rows')
        for r in rows:
            logger.info(f'  {r[0]}  is_crash_resolved={r[1]}')
        return len(rows)

    conn.executemany('''
        INSERT INTO patch_verification
            (run_id, attempt, is_crash_resolved, poc_stdout,
             compile_output_extract, baseline_log, baseline_source)
        VALUES (?, 0, ?, ?, ?, ?, 'arvo.crash_output')
    ''', [(r[0], r[1], r[2], r[3], r[4]) for r in rows])
    conn.commit()
    logger.info(f'backfill: inserted {len(rows)} legacy rows as attempt=0')
    return len(rows)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', default=DB_PATH)
    parser.add_argument('--no-backfill', action='store_true',
                        help='create the table but do not copy legacy verdicts')
    parser.add_argument('--dry-run', action='store_true',
                        help='report what the backfill would insert, change nothing')
    args = parser.parse_args(argv)

    conn = sqlite3.connect(args.db)
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        if args.dry_run:
            # the table has to exist for the NOT EXISTS guard to be answerable
            conn.execute(PATCH_VERIFICATION_DDL)
        else:
            migrate(conn)

        if not args.no_backfill:
            backfill(conn, dry_run=args.dry_run)

        total = conn.execute('SELECT COUNT(*) FROM patch_verification').fetchone()[0]
        by_attempt = conn.execute(
            'SELECT attempt, COUNT(*) FROM patch_verification '
            'GROUP BY attempt ORDER BY attempt').fetchall()
        logger.info(f'patch_verification rows: {total} {dict(by_attempt)}')
    except sqlite3.Error as e:
        logger.error(f'migration failed: {e}')
        conn.rollback()
        return 1
    finally:
        conn.close()
    return 0


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler('patch_verification_upgrade.log'),
                  logging.StreamHandler(sys.stdout)],
    )
    sys.exit(main())
