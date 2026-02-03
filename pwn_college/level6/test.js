let arr = [1.1, 1.1, 1.1];
let obj = {};
let obj_addr = undefined;
let idx = 0;

arr.functionMap((value) => {
    switch (idx) {
        case 0:
            arr[0] = obj;
            idx++;
            %DebugPrint(arr);
            return value;
        case 1:
            obj_addr = value;
            idx++;
            return value;
        default:
            idx++;
            return value;
    }
});

console.log(obj_addr);
%SystemBreak();
