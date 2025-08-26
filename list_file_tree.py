import os
def main():
    """
    Performs a recursive directory listing to map the entire filesystem jail.
    The final map is returned as a single string.
    """

    def generate_tree(path, indent=""):
        # A list to hold the lines of the tree structure for the current path
        tree_lines = []
        try:
            # Get the list of items in the current directory
            items = os.listdir(path)
            # Use a simple sort to make the output consistent
            items.sort()
        except Exception as e:
            # If we can't list a directory (e.g., permissions), note it
            tree_lines.append(f"{indent}└── [Error: {e}]")
            return tree_lines

        for i, item_name in enumerate(items):
            # Determine the prefix for the tree structure (is it the last item?)
            is_last = (i == len(items) - 1)
            prefix = "└── " if is_last else "├── "

            item_path = os.path.join(path, item_name)
            tree_lines.append(f"{indent}{prefix}{item_name}")

            # Check if the item is a directory to recurse into it
            # We can't use os.path.isdir, so we'll infer it by trying to list it.
            try:
                # A trick to check if it's a directory: see if listdir works on it.
                # This is a bit slow but is our only option without stat().
                os.listdir(item_path)
                is_directory = True
            except OSError:
                is_directory = False

            if is_directory:
                # If it's a directory, recurse and add the sub-tree to our lines
                child_indent = "    " if is_last else "│   "
                tree_lines.extend(generate_tree(item_path, indent + child_indent))

        return tree_lines

    # Start the mapping from the current directory '.'
    report = ["--- Filesystem Map ---", "."]
    report.extend(generate_tree('.'))

    final_report_string = "\n".join(report)

    return {"result": final_report_string}