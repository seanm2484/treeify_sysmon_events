from treelib import Node, Tree
import csv
import argparse

data = []
headers = []

def parse_csv(path: str) -> str:
    line_count = 0
    
    with open(path) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if line_count == 0:
                headers = row
                print(headers)
                line_count += 1
            else:
                row.append(line_count)
                data.append(row)
                line_count += 1
    return data

def create_our_node(row: list[str], nodes: dict, c: dict, tree):
    ''' row contains all the data
    nodes is a dict of all the nodes we have created
    '''
    # if this node already is created, skip it
    if nodes.get(row[c['event_data.processid']]):
        print(f"Node {nodes[row[c['event_data.processid']]]} already exists.")
        return nodes[row[c['event_data.processid']]]
    
    # make sure our parent exists
    if not nodes.get(row[c['event_data.parentprocessid']]):
        try:
            # make sure the parent node exists in the data. If it doesnt, call create_our_node again
            # to create the parent node
            parent = next(x for x in data 
                          if x[c['event_data.processid']] == row[c['event_data.parentprocessid']])
            create_our_node(parent, nodes, c, tree)
            printf(f"Parent node node {parent} does not exist.")
        except StopIteration:
            # if our process doesn't have a parent we know about, then create its parent and
            # parent that to 1 (the root)
            parent = 1
            print(f"Our parent node {row[c['event_data.parentprocessid']]} does not exist in the data.\
            Parenting {row[c['event_data.processid']]} to a new version of it's parent, which \
            is parented to 1")
            # create the parent node that doesn't exist
            header = f"[N/A] PID: {row[c['event_data.parentprocessid']]} - Creation Point"
            n = tree.create_node(header, 
                                 row[c['event_data.parentprocessid']], 
                                 parent=1)
            nodes[row[c['event_data.parentprocessid']]] = n
            header = f"[{row[c['record_id']]}] PID: {row[c['event_data.processid']]} - {row[c['event_data.commandline']]}"
            n2 = tree.create_node(header, 
                                  row[c['event_data.processid']],
                                  parent=nodes[row[c['event_data.parentprocessid']]])
            nodes[row[c['event_data.processid']]] = n2
    else:
        # our parent exists, so just add this node to it
        print(f"Node {row[c['event_data.processid']]} \
        Created with parent {row[c['event_data.parentprocessid']]}")
        header = f"[{row[c['record_id']]}] PID: {row[c['event_data.processid']]} - {row[c['event_data.commandline']]}"
        
        n = tree.create_node(header, 
                         row[c['event_data.processid']], 
                         parent=row[c['event_data.parentprocessid']])
    nodes[row[c['event_data.processid']]] = n

    
def main():
    parser = argparse.ArgumentParser(description='treeify csv sysmon data')
    parser.add_argument('-c','--csv', help='path to CSV data', required=True)
    args = vars(parser.parse_args())
    
    data = parse_csv(args['csv'])
    nodes = {}
    ns = []
    c = {'time':0,'event_id':1, 'event_data.image':2, 'event_data.parentcommandline':3,
        'event_data.processid':4, 'event_data.parentprocessid':5, 'event_data.commandline':6,
        'record_id':7}
    PROCESS_CREATION = 1
    event_type = {'2': "process changed file creation time",
                 '3': "network connection",
                 '4': "sysmon service state changed",
                 '22': "DNSEvent"}
    # dummy parent node
    tree = Tree()
    tree.create_node(1, 1)
    for idx, row in enumerate(data[::-1]):
        if row[c['event_id'] == PROCESS_CREATION]:
            node = create_our_node(row, nodes, c, tree)
            ns.append(node)

    # now that we have the process tree, add in the other sysmon events
    for pid, node in nodes.items():
        for event in data:
            if not event[c['event_id']] == '1':
                if event[c['event_data.processid']] == pid:
                    header = f"[{event[c['record_id']]}] Event: {event_type[event[c['event_id']]]}"
                    tree.create_node(header, event[c['record_id']], parent=node)
    tree.show()
    

if __name__ == '__main__':
    main()

