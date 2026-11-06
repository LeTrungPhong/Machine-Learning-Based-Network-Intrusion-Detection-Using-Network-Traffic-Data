"""Graph-based botnet detection package."""

from graph.botnet_graph import (
    GRAPH_FEATURE_COLUMNS,
    build_communication_graph,
    detect_botnet_topology,
    extract_graph_features,
    generate_synthetic_botnet_flows,
    parse_binetflow,
    plot_botnet_graph,
    run_pipeline,
    train_evaluate_graph_models,
)

__all__ = [
    "GRAPH_FEATURE_COLUMNS",
    "build_communication_graph",
    "detect_botnet_topology",
    "extract_graph_features",
    "generate_synthetic_botnet_flows",
    "parse_binetflow",
    "plot_botnet_graph",
    "run_pipeline",
    "train_evaluate_graph_models",
]

