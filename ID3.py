from sklearn import tree
import csv
import graphviz

csvfile = list(csv.reader(open('featureflow.csv')))
x=[]
y=[]
key_row=0
for row in csvfile:
    if(key_row==len(csvfile)-1):
        break
    else:
        x.append(row[0:3])
        y.append(int(row[len(row)-1]))
    key_row += 1

key=0
for item in x:
    x[key]=map(float,item)
    key+=1

print x[0],y[0]

clf = tree.DecisionTreeClassifier()
clf = clf.fit(x, y)
res=clf.predict([[160,150,1000]])
print res
dot_data = tree.export_graphviz(clf, out_file=None,
                         feature_names=['avali','dovomi','sevomi'],
                         class_names=['1','0'],
                         filled=True, rounded=True,
                         special_characters=True)


graph = graphviz.Source(dot_data)
graph

# dot -Tps tree.dot -o outfile.ps