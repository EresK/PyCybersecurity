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

    function pushItem(string memory title, string memory description, uint price) internal {
        items.push(Item(id_sequence++, title, description, price));
    }

    function initItems() internal {
        pushItem("Bread", "Food", 100);
        pushItem("Choco", "Food", 1000);
        pushItem("Truffles", "Something very rare", 1000000000000000000);
    }

    function getItems() public view returns(Item[] memory) {
        return items;
    }

    function addItem(string memory title, string memory description, uint price) external isOwner {
        pushItem(title, description, price);
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