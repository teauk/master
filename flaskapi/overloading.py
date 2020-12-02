def test(a,b=None):
    print(a)
    if b is not None:
        print(b)
test(1)
test(1,2)
path='/a/b/c/d/e/f'
path_='/a/b/c/d'
print(path.split(path_))
list_ = ['image','not_sure']
split_path=''
for folder_name in list_:
    split_path = split_path+'/'+folder_name
    print(split_path)