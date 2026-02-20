import asyncio
from app.engine.graph import build_workflow
from app.models.schemas import ExtractedIntel
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

async def test_graph():
    print("Testing Graph with AsyncSqliteSaver and Context Manager...")
    initial_state = {
        "session_id": "test_session_async_v2",
        "user_message": "Hello, I want to pay using UPI",
        "history": [],
        "scam_detected": False,
        "high_priority": False,
        "scammer_sentiment": 5,
        "selected_persona": "RAJESH",
        "agent_response": "",
        "intel": ExtractedIntel(),
        "is_returning_scammer": False,
        "syndicate_match_score": 0.0,
        "generate_report": False,
        "human_intervention": False,
        "report_url": None,
        "turn_count": 0
    }
    config = {"configurable": {"thread_id": "test_session_async_v2"}}
    
    try:
        async with AsyncSqliteSaver.from_conn_string("db/checkpoints.sqlite") as saver:
            workflow = build_workflow()
            graph = workflow.compile(checkpointer=saver)
            result = await graph.ainvoke(initial_state, config=config)
            print("✅ Graph invoked successfully!")
            print(f"Agent Response: {result['agent_response']}")
    except Exception as e:
        print(f"❌ Graph invocation failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_graph())
