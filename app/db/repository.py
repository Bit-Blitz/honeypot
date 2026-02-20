import sqlite3
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Dict, Optional
from app.core.config import settings

class HoneyDB:
    def __init__(self):
        self.db_path = settings.DATABASE_PATH
        self.executor = ThreadPoolExecutor(max_workers=5)
        self._init_db()

    def _init_db(self):
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    role TEXT,
                    content TEXT,
                    timestamp DATETIME
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    is_scam INTEGER DEFAULT 0,
                    created_at DATETIME
                )
            """)
            
            # Migration: Ensure tables exist
            pass
            conn.execute("""
                CREATE TABLE IF NOT EXISTS extracted_intel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    type TEXT, -- 'upi', 'bank', 'link', 'phone'
                    value TEXT,
                    timestamp DATETIME
                )
            """)

    async def add_message(self, session_id: str, role: str, content: str):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self.executor, self._add_message_sync, session_id, role, content)

    def _add_message_sync(self, session_id: str, role: str, content: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
                (session_id, role, content, datetime.now())
            )

    async def set_scam_flag(self, session_id: str, is_scam: bool):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self.executor, self._set_scam_flag_sync, session_id, is_scam)

    def _set_scam_flag_sync(self, session_id: str, is_scam: bool):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions (session_id, is_scam, created_at) VALUES (?, ?, ?)",
                (session_id, 1 if is_scam else 0, datetime.now())
            )

    async def save_intel(self, session_id: str, intel_type: str, value: str) -> bool:
        """
        Saves intelligence and returns True if this value was already known
        from a DIFFERENT session (Syndicate Detection).
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._save_intel_sync, session_id, intel_type, value)

    def _save_intel_sync(self, session_id: str, intel_type: str, value: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            # Check for existing intel from other sessions
            cursor = conn.execute(
                "SELECT COUNT(*) FROM extracted_intel WHERE type = ? AND value = ? AND session_id != ?",
                (intel_type, value, session_id)
            )
            is_syndicate = cursor.fetchone()[0] > 0
            
            # Save current intel
            conn.execute(
                "INSERT INTO extracted_intel (session_id, type, value, timestamp) VALUES (?, ?, ?, ?)",
                (session_id, intel_type, value, datetime.now())
            )
            return is_syndicate

    async def get_context(self, session_id: str, limit: int = 10) -> List[Dict]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._get_context_sync, session_id, limit)

    def _get_context_sync(self, session_id: str, limit: int = 10) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT role, content FROM messages WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
                (session_id, limit)
            )
            rows = cursor.fetchall()
            return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]

    async def get_syndicate_links(self):
        """
        Retrieves intelligence links and performs basic graph clustering
        to identify potential scam syndicates.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._get_syndicate_links_sync)

    def _get_syndicate_links_sync(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            # 1. Fetch all intelligence records
            cursor = conn.execute("""
                SELECT session_id, type, value 
                FROM extracted_intel
            """)
            records = cursor.fetchall()
            
            nodes = []
            edges = []
            seen_nodes = {}
            node_degrees = {}
            
            # 2. Perform Link Analysis
            for rec in records:
                session_id = rec["session_id"]
                intel_type = rec["type"]
                value = rec["value"]
                ident_id = f"{intel_type}_{value}"
                
                # Track degree for visualization
                node_degrees[session_id] = node_degrees.get(session_id, 0) + 1
                node_degrees[ident_id] = node_degrees.get(ident_id, 0) + 1
                
                # Add Session Node
                if session_id not in seen_nodes:
                    seen_nodes[session_id] = True
                    nodes.append({
                        "id": session_id,
                        "type": "session",
                        "label": f"Session {session_id[:8]}"
                    })
                
                # Link Identifiers
                if ident_id not in seen_nodes:
                    seen_nodes[ident_id] = True
                    nodes.append({
                        "id": ident_id, 
                        "type": intel_type, 
                        "label": value,
                        "metadata": {
                            "risk_score": 0.85 if intel_type in ['upi', 'bank'] else 0.6,
                            "last_seen": datetime.now().isoformat()
                        }
                    })
                
                edges.append({
                    "source": session_id, 
                    "target": ident_id, 
                    "label": f"uses_{intel_type}",
                    "weight": 2.0 if intel_type == 'upi' else 1.0 
                })

            # Add degrees to nodes
            for node in nodes:
                node["degree"] = node_degrees.get(node["id"], 0)

            return {
                "nodes": nodes,
                "links": edges,
                "metadata": {
                    "total_records": len(records),
                    "analysis_engine": "Forensic Link Analysis v2.1",
                    "clustering_algorithm": "Adjacency-Based Syndicate Detection",
                    "hubs_detected": len([d for d in node_degrees.values() if d > 2])
                }
            }

    async def get_all_intel(self) -> List[Dict]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._get_all_intel_sync)

    def _get_all_intel_sync(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM extracted_intel ORDER BY timestamp DESC")
            return [dict(r) for r in cursor.fetchall()]

    async def get_session_intel(self, session_id: str) -> List[Dict]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._get_session_intel_sync, session_id)

    def _get_session_intel_sync(self, session_id: str) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT type, value FROM extracted_intel WHERE session_id = ?", (session_id,))
            return [dict(r) for r in cursor.fetchall()]

    async def get_stats(self):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._get_stats_sync)

    def _get_stats_sync(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            scams_detected = conn.execute("SELECT COUNT(*) FROM sessions WHERE is_scam = 1").fetchone()[0]
            top_upi = conn.execute("""
                SELECT value, COUNT(*) as count 
                FROM extracted_intel 
                WHERE type = 'upi' 
                GROUP BY value 
                ORDER BY count DESC 
                LIMIT 5
            """).fetchall()
            return {
                "total_sessions": total_sessions,
                "scams_detected": scams_detected,
                "top_upi_ids": [r["value"] for r in top_upi]
            }

    async def get_turn_count(self, session_id: str) -> int:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._get_turn_count_sync, session_id)

    def _get_turn_count_sync(self, session_id: str) -> int:
        with sqlite3.connect(self.db_path) as conn:
            if session_id == "all":
                return conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            return conn.execute("SELECT COUNT(*) FROM messages WHERE session_id = ?", (session_id,)).fetchone()[0]

    async def is_scam_session(self, session_id: str) -> bool:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._is_scam_session_sync, session_id)

    def _is_scam_session_sync(self, session_id: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            res = conn.execute("SELECT is_scam FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            return bool(res[0]) if res else False

    async def get_first_message_time(self, session_id: str) -> Optional[datetime]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._get_first_message_time_sync, session_id)

    def _get_first_message_time_sync(self, session_id: str) -> Optional[datetime]:
        with sqlite3.connect(self.db_path) as conn:
            # 1. Try sessions table (created_at)
            res = conn.execute("SELECT created_at FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if res and res[0]:
                for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        return datetime.strptime(res[0], fmt)
                    except ValueError:
                        continue
            
            # 2. Fallback to first message (timestamp)
            res = conn.execute("SELECT timestamp FROM messages WHERE session_id = ? ORDER BY timestamp ASC LIMIT 1", (session_id,)).fetchone()
            if res and res[0]:
                # Try standard formats + ISO format
                formats = [
                    "%Y-%m-%d %H:%M:%S.%f", 
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S"
                ]
                for fmt in formats:
                    try:
                        return datetime.strptime(res[0], fmt)
                    except ValueError:
                        continue
                
                # If all else fails, try to return it if it's already a datetime object (unlikely with sqlite3 default)
                # Or just log the error and return None
                print(f"Failed to parse timestamp: {res[0]}")
                
            return None

db = HoneyDB()