from typing import Any, Dict

from agent.state import AgentState
from agent.nodes import (
    parse_command_node,
    get_wallet_node,
    check_balance_node,
    send_transaction_node,
    sign_message_node,
    request_testnet_tokens_node,
)
import logging

logger = logging.getLogger(__name__)


def route_by_operation(state: AgentState) -> str:
    """
    Routes execution based on the detected operation.
    """
    operation = state.get('operation')

    if not operation:
        logger.warning("Operation not recognized")
        return 'end'

    operation_routes = {
        'get_wallet': 'get_wallet',
        'check_balance': 'check_balance',
        'send_transaction': 'send_tx',
        'sign_message': 'sign_message',
        'request_testnet_tokens': 'request_tokens',
    }

    route = operation_routes.get(operation, 'end')
    logger.info(f"Routing to node: {route}")

    return route


def should_get_wallet(state: AgentState) -> str:
    """
    Determines whether a wallet needs to be fetched before the operation.
    """
    operation = state.get('operation')

    operations_needing_wallet = [
        'check_balance',
        'send_transaction',
        'sign_message',
        'request_testnet_tokens',
    ]

    if operation in operations_needing_wallet and not state.get('wallet_id'):
        return 'get_wallet'

    return 'route'


class AgentGraph:
    """Minimal execution graph without a dependency on langgraph."""

    async def ainvoke(self, initial_state: AgentState) -> AgentState:
        state: Dict[str, Any] = dict(initial_state)

        parse_result = await parse_command_node(state)
        state.update(parse_result)

        if parse_result.get('error'):
            return state  # stop execution on parse error

        if should_get_wallet(state) == 'get_wallet':
            wallet_result = await get_wallet_node(state)
            state.update(wallet_result)

            if wallet_result.get('error'):
                return state

        route = route_by_operation(state)

        if route == 'get_wallet':
            wallet_result = await get_wallet_node(state)
            state.update(wallet_result)
            return state

        node_handlers = {
            'check_balance': check_balance_node,
            'send_tx': send_transaction_node,
            'sign_message': sign_message_node,
            'request_tokens': request_testnet_tokens_node,
        }

        handler = node_handlers.get(route)

        if handler is None:
            logger.info("Graph execution finished without additional steps")
            return state

        node_result = await handler(state)
        state.update(node_result)

        return state  # type: ignore[return-value]


def create_agent_graph() -> AgentGraph:
    """Create an agent graph instance."""

    return AgentGraph()

