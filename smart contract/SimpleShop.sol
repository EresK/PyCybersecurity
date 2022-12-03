// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract SimpleShop {
    address owner;

    struct Item {
        uint itemId;
        string title;
        string description;
        uint price;
    }

    Item[] items;

    uint id_sequence;

    constructor() {
        owner = msg.sender;
        initItems();
    }

    modifier isOwner() {
        require(msg.sender == owner, "Prohibited, only for owner!");
        _;
    }

    function initItems() internal {
        items.push(Item(id_sequence++, "Bread", "Food", 100));
        items.push(Item(id_sequence++, "Choco", "Food", 1000));
        items.push(Item(id_sequence++, "Truffles", "Something very rare", 1000000000000000000));
    }

    function getItems() public view returns(Item[] memory) {
        return items;
    }

    function addItem(Item memory item) external isOwner {
        items.push(item);
    }

    function withdrawAll() external payable isOwner {
        address payable _to = payable(owner);
        _to.transfer(address(this).balance);
    }

    function buyItem(uint itemId) external payable {
        for (uint i = 0; i < items.length; i++) {
            Item memory currItem = items[i];

            if (currItem.itemId == itemId) {
                require(currItem.price == msg.value, "Please, send accurate amount.");
                return;
            }
        }

        revert("There is no item with such id.");
    }
}