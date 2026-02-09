import networkx as nx
import matplotlib.pyplot as plt
import json
import argparse
import os
from algos_details import details
import networkx.drawing.nx_pydot as pydot

SKIP_KEYS = [
    "Classic Security Level", "Functions", "Mode", 
    "certification level", "NIST_Security_Category", "Primitive"
]
HASH_FUNCTIONS = ["SHA-256", "SHA-512", "MD5", "SHA-1", "SHA3-256", "SHA3-512, SHA384"]
PROTOCOLS = ["TLS", "IPSec", "HTTPS", "SSH", "SSL"]

class Counter:
    def __init__(self):
        self.count = 0

    def increment(self):
        self.count += 1
        return self.count

class GraphVisualizer:
    def __init__(self, graph):
        self.graph = graph

    def draw(self):
        print("Starting to draw the graph...")
        pos = pydot.pydot_layout(self.graph, prog='dot')
        node_colors = []
        labels = {}

        for node in self.graph.nodes():
            labels[node] = self.graph.nodes[node].get('label', node)
            level = self.graph.nodes[node].get('level', 0)
            if level == 0:
                node_colors.append("gold")
            elif level == 1:
                node_colors.append("skyblue")
            elif level == 2:
                node_colors.append("lightgreen")
            elif level == 3:
                node_colors.append("lightcoral")
            else:
                node_colors.append("lightgray")

        plt.figure(figsize=(18, 14))
        nx.draw(
            self.graph,
            pos,
            with_labels=True,
            labels=labels,
            node_color=node_colors,
            node_size=3000,
            edge_color="gray",
            font_size=12,
            font_weight="bold",
            font_color="black",
            alpha=0.8,
            width=2,
        )

        plt.title("Cryptographic Algorithm Tree", fontsize=18)
        plt.savefig('./plots/algorithm_tree.png', format='PNG')
        plt.show()
        plt.close()
        print("Graph drawing complete. Image saved to './plots/algorithm_tree.png'")

    def search(self, label, current_node="Root", path=None):
        if path is None:
            path = []

        path.append(current_node)
        current_node_data = None
        for node in self.graph.nodes():
            if self.graph.nodes[node].get('label') == label:
                current_node_data = self.graph.nodes[node]
                current_node = node
                break
        
        if current_node_data is None:
            print(f"Node with label '{label}' not found.")
            return None

        print(f"Path to {label}: {' -> '.join(path)}")
        node_data = self.graph.nodes[current_node]

        if 'json' in node_data:
            json_data = node_data['json']
            for key in SKIP_KEYS:
                if key in json_data:
                    print(f"{key}: {json_data[key]}")
        
        return node_data, path

def build_tree(graph, parent, data, counter, level=1):
    for key, value in data.items():
        if key in SKIP_KEYS:
            continue

        if key == 'bits':
            if isinstance(value, list):
                for bit in value:
                    combined_label = f"{parent.split('_')[0]}_{bit}"
                    bit_id = f"{combined_label}_{counter.increment()}"
                    
                    if not graph.has_node(bit_id):
                        graph.add_node(bit_id, label=str(bit), level=level + 1)
                        graph.add_edge(parent, bit_id)
                        print(f"Added node from bits: {bit_id} with label: {bit} at level {level + 1}")
                    else:
                        print(f"Node {bit_id} already exists.")
        elif isinstance(value, dict):
            node_id = f"{key}_{counter.increment()}"
            if not graph.has_node(node_id):
                graph.add_node(node_id, label=key, json=value, level=level)
                graph.add_edge(parent, node_id)
                print(f"Added node: {node_id} with label: {key} at level {level}")
                build_tree(graph, node_id, value, counter, level + 1)
            else:
                print(f"Node {node_id} already exists.")
        elif isinstance(value, list):
            for item in value:
                item_id = f"{item}_{counter.increment()}"
                if not graph.has_node(item_id):
                    graph.add_node(item_id, label=item, level=level + 1)
                    graph.add_edge(parent, item_id)
                    print(f"Added node from list: {item_id} with label: {item} at level {level + 1}")
                else:
                    print(f"Node {item_id} already exists.")
        else:
            continue

def load_graph_from_json():
    if os.path.exists('./plots/algorithm_tree.json'):
        with open('./plots/algorithm_tree.json', 'r') as f:
            data = json.load(f)
        return nx.readwrite.json_graph.node_link_graph(data, edges="edges")
    return None

def save_graph_to_json(graph):
    data = nx.readwrite.json_graph.node_link_data(graph, edges="edges")  # Explicitly use 'edges' for saving
    with open('./plots/algorithm_tree.json', "w") as f:
        json.dump(data, f, indent=4)

def handle_dynamic_path(graph, search_path, counter):
    current_node = None
    path_data = []
    created_nodes = []
    additional_info = {}  # Store additional information here

    # Normalize input path for case-insensitive comparison
    normalized_path = [part.lower() for part in search_path]

    # Determine if the input is a hash function or protocol
    first_label = normalized_path[0]
    if first_label in [hf.lower() for hf in HASH_FUNCTIONS]:
        category_node = "Hash Function"
    elif first_label in [protocol.lower() for protocol in PROTOCOLS]:
        category_node = "Protocol"
    else:
        category_node = None  # Treat as general algorithm

    if category_node:
        # Search or create the category node
        for node in graph.nodes:
            if graph.nodes[node].get('label', '').lower() == category_node.lower():
                current_node = node
                break

        if current_node is None:
            current_node = f"{category_node}_{counter.increment()}"
            graph.add_node(current_node, label=category_node, level=1)
            graph.add_edge("Root", current_node)
            print(f"Created category node '{current_node}' with label '{category_node}'.")

        # Add the specific item under the category
        specific_label = search_path[0]
        specific_node = None
        for node in graph.successors(current_node):
            if graph.nodes[node].get('label', '').lower() == specific_label.lower():
                specific_node = node
                break

        if specific_node is None:
            specific_node = f"{specific_label}_{counter.increment()}"
            graph.add_node(specific_node, label=specific_label, level=2)
            graph.add_edge(current_node, specific_node)
            print(f"Created node '{specific_node}' with label '{specific_label}' under '{category_node}'.")
            created_nodes.append(specific_node)
        else:
            print(f"Found existing node '{specific_node}' with label '{specific_label}'.")

        path_data.append(current_node)
        path_data.append(specific_node)
    else:
        # Handle general algorithm (unchanged logic)
        algorithm_label = normalized_path[0]
        for node in graph.nodes:
            if graph.nodes[node].get('label', '').lower() == algorithm_label:
                current_node = node
                break

        if current_node is None:
            is_symmetric = algorithm_label in [alg.lower() for alg in ['AES', 'Camellia', 'Blowfish']]
            category_node = "Symmetric" if is_symmetric else "Asymmetric"
            
            current_node = f"{search_path[0]}_{counter.increment()}"
            graph.add_node(
                current_node,
                label=search_path[0],
                level=3
            )
            graph.add_edge(category_node, current_node)
            print(f"Created algorithm node '{current_node}' with label '{search_path[0]}' under '{category_node}'.")
            created_nodes.append(current_node)

        path_data.append(current_node)

        for part, normalized_part in zip(search_path[1:], normalized_path[1:]):
            found_node = None

            for successor in graph.successors(current_node):
                if graph.nodes[successor].get('label', '').lower() == normalized_part:
                    found_node = successor
                    break

            if found_node is None:
                new_node_id = f"{part}_{counter.increment()}"
                node_level = graph.nodes[current_node].get('level', 0) + 1
                graph.add_node(
                    new_node_id,
                    label=part,
                    level=node_level
                )
                graph.add_edge(current_node, new_node_id)
                print(f"Created node '{new_node_id}' with label '{part}' and linked it to '{current_node}'.")
                current_node = new_node_id
                created_nodes.append(new_node_id)
            else:
                if found_node not in graph.successors(current_node):
                    graph.add_edge(current_node, found_node)
                    print(f"Linked existing node '{found_node}' with label '{part}' to '{current_node}'.")
                current_node = found_node
                print(f"Reusing existing node '{found_node}' with label '{part}'.")

            path_data.append(current_node)

    # Collect additional information in the 'additional_info' dictionary
    node_data = graph.nodes[current_node]
    if 'json' in node_data:
        json_data = node_data['json']
        print("Additional Information:")
        for key in SKIP_KEYS:
            if key in json_data:
                # Store each skipped key's data in the additional_info variable
                additional_info[key] = json_data[key]
                print(f"{key}: {json_data[key]}")

    print(f"Processed path: {' -> '.join([graph.nodes[node]['label'] for node in path_data])}")
    if created_nodes:
        print(f"New nodes added: {', '.join([graph.nodes[node]['label'] for node in created_nodes])}")
    else:
        print("No new nodes were added. Path already exists.")

    return path_data, additional_info

def parse_arguments():
    parser = argparse.ArgumentParser(description="Generate and visualize the cryptographic algorithm tree.")
    parser.add_argument("path", help="The path to search in the format 'Algorithm_SubAlgorithm_Key' (e.g., 'AES_cbc_128')")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    search_path = args.path.split('_')  # Split the provided path into its components (e.g., ['AES', 'ccm', '128'])

    # Try to load the graph
    G = load_graph_from_json()

    # Create the counter object before the dynamic path handler
    counter = Counter()

    if G is None:
        print("Graph not found, building a new one from details...")
        G = nx.DiGraph()
        root_node = "Root"
        G.add_node(root_node, label=root_node, level=0)

        # Creating main nodes under root
        print("Adding primary nodes under the root...")
        G.add_node("Algorithms", label="Algorithms", level=1)
        G.add_node("Hash Function", label="Hash Function", level=1)
        G.add_node("Protocol", label="Protocol", level=1)
        G.add_edge(root_node, "Algorithms")
        G.add_edge(root_node, "Hash Function")
        G.add_edge(root_node, "Protocol")

        # Create Symmetric and Asymmetric categories
        symmetric_node = "Symmetric"
        asymmetric_node = "Asymmetric"
        G.add_node(symmetric_node, label="Symmetric", level=2)
        G.add_node(asymmetric_node, label="Asymmetric", level=2)
        G.add_edge("Algorithms", symmetric_node)
        G.add_edge("Algorithms", asymmetric_node)

        print("Building the tree structure under 'Algorithms'...")
        for algorithm, details_data in details.items():
            algorithm_node = f"{algorithm}_{counter.increment()}"
            # Check if the algorithm is symmetric or asymmetric
            category_node = symmetric_node if algorithm in ['AES', 'Camellia', 'Blowfish'] else asymmetric_node
            
            G.add_node(algorithm_node, label=algorithm, json=details_data, level=3)
            G.add_edge(category_node, algorithm_node)

            print(f"Added algorithm node: {algorithm_node} with label: {algorithm} under '{category_node}'.")

            if isinstance(details_data, dict):
                build_tree(G, algorithm_node, details_data, counter)

    # Search and dynamically add missing nodes
    path_data = handle_dynamic_path(G, search_path, counter)

    visualizer = GraphVisualizer(G)
    visualizer.draw()

    save_graph_to_json(G)

    print("Graph saved as JSON at './plots/algorithm_tree.json'")